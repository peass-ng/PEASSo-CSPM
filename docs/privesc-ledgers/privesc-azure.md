# Azure / Entra ID privilege-escalation ledger (HackTricks Cloud 0b3633117413069d93b713d2a98a9e16b1d189f3)

Every heading of `src/pentesting-cloud/azure-security/az-privilege-escalation/**` plus every technique-bearing heading of the other Azure pages (post-exploitation, persistence, services, lateral movement / hybrid, cross-tenant, unauthenticated) mapped to catalog ids in `peaso/privesc/catalog/azure/*.yaml` or to a reason. Keys are relative to `src/pentesting-cloud/azure-security/`.

Status: MAPPED (catalog ids) · EXCLUDED (reviewed, not a principal->principal escalation, reason given) · NEEDS SCHEMA (see section at the end) · STRUCTURAL (title/intro/references/enumeration/how-to subheading) · SUBSECTION (inherits the parent technique's mapping).

Totals: 2537 rows; technique rows (MAPPED+EXCLUDED+NEEDS SCHEMA) 1506; EXCLUDED 1304, MAPPED 202, NEEDS_SCHEMA 0, STRUCTURAL 741, SUBSECTION 290

## az-privilege-escalation/README.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/README.md#az---privilege-escalation` | Az - Privilege Escalation |  | STRUCTURAL | title/reference/intro heading |
| `az-privilege-escalation/README.md#entra-id-and-azure-iam` | Entra ID and Azure IAM |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/README.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-privilege-escalation/az-ai-foundry-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-ai-foundry-privesc.md#az---ai-foundry-ai-hubs-azure-openai--ai-search-privesc` | Az - AI Foundry, AI Hubs, Azure OpenAI & AI Search Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-ai-foundry-privesc.md#ai-foundry-ai-hubs-azure-openai--ai-search` | AI Foundry, AI Hubs, Azure OpenAI & AI Search |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-ai-foundry-privesc.md#microsoftmachinelearningservicesworkspaceshubswrite-microsoftmachinelearningservicesworkspaceswrite-microsoftmanagedidentityuserassignedidentitiesassignaction` | `Microsoft.MachineLearningServices/workspaces/hubs/write`, `Microsoft.MachineLearningServices/workspaces/write`, `Microsoft.ManagedIdentity/userAssignedIdentities/assign/action` | Microsoft.MachineLearningServices/workspaces/hubs/write,Microsoft.MachineLearningServices/workspaces/write,Microsoft.ManagedIdentity/userAssignedIdentities/assign/action | EXCLUDED | Attachment alone does not expose the identity to user code; the code-execution paths are modelled separately. |
| `az-privilege-escalation/az-ai-foundry-privesc.md#enumeration` | Enumeration |  | STRUCTURAL | section/how-to heading; no technique |
| `az-privilege-escalation/az-ai-foundry-privesc.md#exploitation` | Exploitation |  | STRUCTURAL | section/how-to heading; no technique |
| `az-privilege-escalation/az-ai-foundry-privesc.md#option-1-online-endpoints-requires-onlineendpointswrite--deploymentswrite` | Option 1: Online Endpoints (requires `onlineEndpoints/write` + `deployments/write`) | Microsoft.MachineLearningServices/workspaces/onlineEndpoints/deployments/write,Microsoft.MachineLearningServices/workspaces/onlineEndpoints/write | SUBSECTION | of #microsoftmachinelearningservicesworkspaceshubswrite-microsoftmachinelearningservicesworkspaceswrite-microsoftmanagedidentityuserassignedidentitiesassignaction: EXCLUDED Attachment alone does not expose the identity to user code; the code-execution paths are modelled separately. |
| `az-privilege-escalation/az-ai-foundry-privesc.md#option-2-ml-jobs-requires-jobswrite` | Option 2: ML Jobs (requires `jobs/write`) | Microsoft.MachineLearningServices/workspaces/jobs/write | SUBSECTION | of #microsoftmachinelearningservicesworkspaceshubswrite-microsoftmachinelearningservicesworkspaceswrite-microsoftmanagedidentityuserassignedidentitiesassignaction: EXCLUDED Attachment alone does not expose the identity to user code; the code-execution paths are modelled separately. |
| `az-privilege-escalation/az-ai-foundry-privesc.md#option-3-compute-instances-requires-computeswrite` | Option 3: Compute Instances (requires `computes/write`) | Microsoft.MachineLearningServices/workspaces/computes/write | SUBSECTION | of #microsoftmachinelearningservicesworkspaceshubswrite-microsoftmachinelearningservicesworkspaceswrite-microsoftmanagedidentityuserassignedidentitiesassignaction: EXCLUDED Attachment alone does not expose the identity to user code; the code-execution paths are modelled separately. |
| `az-privilege-escalation/az-ai-foundry-privesc.md#microsoftmachinelearningservicesworkspacesonlineendpointstokenaction` | `Microsoft.MachineLearningServices/workspaces/onlineEndpoints/token/action` | Microsoft.MachineLearningServices/workspaces/onlineEndpoints/token/action | EXCLUDED | Scoring access to one endpoint; data/cost impact only. |
| `az-privilege-escalation/az-ai-foundry-privesc.md#enumeration-1` | Enumeration |  | STRUCTURAL | section/how-to heading; no technique |
| `az-privilege-escalation/az-ai-foundry-privesc.md#exploitation-1` | Exploitation |  | STRUCTURAL | section/how-to heading; no technique |
| `az-privilege-escalation/az-ai-foundry-privesc.md#microsoftmachinelearningservicesworkspacesserverlessendpointslistkeysaction` | `Microsoft.MachineLearningServices/workspaces/serverlessEndpoints/listKeys/action` | Microsoft.MachineLearningServices/workspaces/serverlessEndpoints/listKeys/action | EXCLUDED | Inference keys; data/cost impact only. |
| `az-privilege-escalation/az-ai-foundry-privesc.md#enumeration-2` | Enumeration |  | STRUCTURAL | section/how-to heading; no technique |
| `az-privilege-escalation/az-ai-foundry-privesc.md#exploitation-2` | Exploitation |  | STRUCTURAL | section/how-to heading; no technique |
| `az-privilege-escalation/az-ai-foundry-privesc.md#microsoftmachinelearningservicesworkspacesread--microsoftmachinelearningservicesworkspacescomputesapplicationaccessaction` | `Microsoft.MachineLearningServices/workspaces/read` + `Microsoft.MachineLearningServices/workspaces/computes/applicationaccess/action` | Microsoft.MachineLearningServices/workspaces/computes/applicationaccess/action,Microsoft.MachineLearningServices/workspaces/read | MAPPED | `azure-ml-compute-application-access` |
| `az-privilege-escalation/az-ai-foundry-privesc.md#enumeration-and-no-compute-read-fallback` | Enumeration and no-compute-read fallback |  | SUBSECTION | of #microsoftmachinelearningservicesworkspacesread--microsoftmachinelearningservicesworkspacescomputesapplicationaccessaction: MAPPED azure-ml-compute-application-access |
| `az-privilege-escalation/az-ai-foundry-privesc.md#exploitation-3` | Exploitation |  | STRUCTURAL | section/how-to heading; no technique |
| `az-privilege-escalation/az-ai-foundry-privesc.md#azure-ml-v1-environment-registry-credentials` | Azure ML V1 environment registry credentials | Microsoft.MachineLearningServices/workspaces/environments/read,Microsoft.MachineLearningServices/workspaces/environments/readSecrets/action,Microsoft.MachineLearningServices/workspaces/metadata/secrets/read | EXCLUDED | Registry credential disclosure; image poisoning is second-order. |
| `az-privilege-escalation/az-ai-foundry-privesc.md#enumeration-and-known-name-fallback` | Enumeration and known-name fallback |  | SUBSECTION | of #azure-ml-v1-environment-registry-credentials: EXCLUDED Registry credential disclosure; image poisoning is second-order. |
| `az-privilege-escalation/az-ai-foundry-privesc.md#exploitation-4` | Exploitation |  | STRUCTURAL | section/how-to heading; no technique |
| `az-privilege-escalation/az-ai-foundry-privesc.md#ai-foundry-shared-connection-credential-recovery` | AI Foundry shared-connection credential recovery | Microsoft.CognitiveServices/accounts/AIServices/connections/listSecrets/action,Microsoft.CognitiveServices/accounts/AIServices/connections/read | EXCLUDED | Strict principal-boundary audit: The credential_stored_in_scope selector has no exact usable credential and identified target-principal evidence enforcement for this technique; a secret read or arbitrary configuration change alone is not an established principal escalation. |
| `az-privilege-escalation/az-ai-foundry-privesc.md#enumeration-and-no-arm-read-fallback` | Enumeration and no-ARM-read fallback |  | SUBSECTION | of #ai-foundry-shared-connection-credential-recovery: MAPPED azure-foundry-shared-connection-secrets |
| `az-privilege-escalation/az-ai-foundry-privesc.md#exploitation-5` | Exploitation |  | STRUCTURAL | section/how-to heading; no technique |
| `az-privilege-escalation/az-ai-foundry-privesc.md#stored-azure-openai-response-disclosure` | Stored Azure OpenAI response disclosure | Microsoft.CognitiveServices/accounts/OpenAI/responses/read | EXCLUDED | Data read. |
| `az-privilege-escalation/az-ai-foundry-privesc.md#foundry-project-response-disclosure-through-aiservicesagentsread` | Foundry project response disclosure through `AIServices/agents/read` | Microsoft.CognitiveServices/accounts/AIServices/agents/read | EXCLUDED | Data read. |
| `az-privilege-escalation/az-ai-foundry-privesc.md#stored-completions-are-not-a-validated-current-disclosure-path` | Stored completions are not a validated current disclosure path | Microsoft.CognitiveServices/accounts/OpenAI/stored-completions/action,Microsoft.CognitiveServices/accounts/OpenAI/stored-completions/read | SUBSECTION | of #foundry-project-response-disclosure-through-aiservicesagentsread: EXCLUDED Data read. |
| `az-privilege-escalation/az-ai-foundry-privesc.md#microsoftmachinelearningservicesworkspacesonlineendpointswrite-microsoftmachinelearningservicesworkspacesonlineendpointsdeploymentswrite-microsoftmachinelearningservicesworkspacesread` | `Microsoft.MachineLearningServices/workspaces/onlineEndpoints/write`, `Microsoft.MachineLearningServices/workspaces/onlineEndpoints/deployments/write`, `Microsoft.MachineLearningServices/workspaces/read` | Microsoft.MachineLearningServices/workspaces/onlineEndpoints/deployments/write,Microsoft.MachineLearningServices/workspaces/onlineEndpoints/write,Microsoft.MachineLearningServices/workspaces/read | MAPPED | `azure-ml-online-deployment-existing-endpoint` `azure-ml-online-endpoint-create-with-user-assigned-identity` |
| `az-privilege-escalation/az-ai-foundry-privesc.md#enumeration-3` | Enumeration |  | STRUCTURAL | section/how-to heading; no technique |
| `az-privilege-escalation/az-ai-foundry-privesc.md#exploitation-6` | Exploitation |  | STRUCTURAL | section/how-to heading; no technique |
| `az-privilege-escalation/az-ai-foundry-privesc.md#microsoftmachinelearningservicesworkspacesjobswrite-and-target-read-permissions` | `Microsoft.MachineLearningServices/workspaces/jobs/write` (and target read permissions) | Microsoft.MachineLearningServices/workspaces/jobs/write | EXCLUDED | `azure-ml-jobs-write-compute-identity`, `azure-ml-jobs-write-serverless-workspace-uami` NEEDS SCHEMA: exact compute selection, successful job, reached identity token, and new action are unverified. |
| `az-privilege-escalation/az-ai-foundry-privesc.md#enumeration-4` | Enumeration |  | STRUCTURAL | section/how-to heading; no technique |
| `az-privilege-escalation/az-ai-foundry-privesc.md#exploitation-7` | Exploitation |  | STRUCTURAL | section/how-to heading; no technique |
| `az-privilege-escalation/az-ai-foundry-privesc.md#microsoftmachinelearningservicesworkspacescomputeswrite` | `Microsoft.MachineLearningServices/workspaces/computes/write` | Microsoft.MachineLearningServices/workspaces/computes/write | MAPPED | `azure-ml-compute-create-with-user-assigned-identity` |
| `az-privilege-escalation/az-ai-foundry-privesc.md#enumeration-5` | Enumeration |  | STRUCTURAL | section/how-to heading; no technique |
| `az-privilege-escalation/az-ai-foundry-privesc.md#exploitation-8` | Exploitation |  | STRUCTURAL | section/how-to heading; no technique |
| `az-privilege-escalation/az-ai-foundry-privesc.md#microsoftmachinelearningservicesworkspacesconnectionslistsecretsaction-microsoftmachinelearningservicesworkspacesdatastoreslistsecretsaction` | `Microsoft.MachineLearningServices/workspaces/connections/listsecrets/action`, `Microsoft.MachineLearningServices/workspaces/datastores/listSecrets/action` | Microsoft.MachineLearningServices/workspaces/connections/listsecrets/action,Microsoft.MachineLearningServices/workspaces/datastores/listSecrets/action | EXCLUDED | Strict principal-boundary audit: The credential_stored_in_scope selector has no exact usable credential and identified target-principal evidence enforcement for this technique; a secret read or arbitrary configuration change alone is not an established principal escalation. |
| `az-privilege-escalation/az-ai-foundry-privesc.md#microsoftmachinelearningservicesworkspaceslistkeysaction-and-microsoftmachinelearningservicesworkspacesliststorageaccountkeysaction` | `Microsoft.MachineLearningServices/workspaces/listKeys/action` and `Microsoft.MachineLearningServices/workspaces/listStorageAccountKeys/action` | Microsoft.MachineLearningServices/workspaces/listKeys/action,Microsoft.MachineLearningServices/workspaces/listStorageAccountKeys/action | EXCLUDED | Storage key disclosure; data access. |
| `az-privilege-escalation/az-ai-foundry-privesc.md#microsoftcognitiveservicesaccountsconnectionslistsecretsaction-and-microsoftcognitiveservicesaccountsprojectsconnectionslistsecretsaction` | `Microsoft.CognitiveServices/accounts/connections/listsecrets/action` and `Microsoft.CognitiveServices/accounts/projects/connections/listsecrets/action` | Microsoft.CognitiveServices/accounts/connections/listsecrets/action,Microsoft.CognitiveServices/accounts/projects/connections/listsecrets/action | EXCLUDED | Covered by azure-ml-connection-secrets. |
| `az-privilege-escalation/az-ai-foundry-privesc.md#microsoftcognitiveservicesaccountslistkeysaction--microsoftcognitiveservicesaccountsregeneratekeyaction` | `Microsoft.CognitiveServices/accounts/listKeys/action` \| `Microsoft.CognitiveServices/accounts/regenerateKey/action` | Microsoft.CognitiveServices/accounts/listKeys/action,Microsoft.CognitiveServices/accounts/regenerateKey/action | EXCLUDED | Service API keys; no identity gain. |
| `az-privilege-escalation/az-ai-foundry-privesc.md#microsoftsearchsearchserviceslistadminkeysaction--microsoftsearchsearchservicesregenerateadminkeyaction` | `Microsoft.Search/searchServices/listAdminKeys/action` \| `Microsoft.Search/searchServices/regenerateAdminKey/action` | Microsoft.Search/searchServices/listAdminKeys/action,Microsoft.Search/searchServices/regenerateAdminKey/action | EXCLUDED | Search data-plane keys; data access/poisoning. |
| `az-privilege-escalation/az-ai-foundry-privesc.md#microsoftsearchsearchservicesindexesdocumentsread--microsoftsearchsearchservicesindexescontentsecurityelevatedoperationsread` | `Microsoft.Search/searchServices/indexes/documents/read` + `Microsoft.Search/searchServices/indexes/contentSecurity/elevatedOperations/read` | Microsoft.Search/searchServices/indexes/contentSecurity/elevatedOperations/read,Microsoft.Search/searchServices/indexes/documents/read | EXCLUDED | Data read bypassing document ACLs. |
| `az-privilege-escalation/az-ai-foundry-privesc.md#find-the-target-without-management-plane-read` | Find the target without management-plane read |  | SUBSECTION | of #microsoftsearchsearchservicesindexesdocumentsread--microsoftsearchsearchservicesindexescontentsecurityelevatedoperationsread: EXCLUDED Data read bypassing document ACLs. |
| `az-privilege-escalation/az-ai-foundry-privesc.md#microsoftsearchsearchservicesskillsetswrite` | `Microsoft.Search/searchServices/skillsets/write` | Microsoft.Search/searchServices/indexers/write,Microsoft.Search/searchServices/skillsets/write | EXCLUDED | Duplicate Search skillset route; NEEDS SCHEMA for exact skill execution, audience-bound usable token, and newly allowed action. |
| `az-privilege-escalation/az-ai-foundry-privesc.md#known-name-fallback-without-search-read` | Known-name fallback without Search read |  | SUBSECTION | of #microsoftsearchsearchservicesskillsetswrite: EXCLUDED Duplicate of azure-ai-search-skillset-write-identity-token (ai_search.yaml). |
| `az-privilege-escalation/az-ai-foundry-privesc.md#microsoftsearchsearchserviceslistquerykeysaction--microsoftsearchsearchservicescreatequerykeyaction` | `Microsoft.Search/searchServices/listQueryKeys/action` \| `Microsoft.Search/searchServices/createQueryKey/action` | Microsoft.Search/searchServices/createQueryKey/action,Microsoft.Search/searchServices/listQueryKeys/action | EXCLUDED | Data read. |
| `az-privilege-escalation/az-ai-foundry-privesc.md#data-asset-metadata-permissions-are-not-standalone-poisoning` | Data-asset metadata permissions are not standalone poisoning | Microsoft.MachineLearningServices/workspaces/data/versions/write,Microsoft.MachineLearningServices/workspaces/data/write,Microsoft.MachineLearningServices/workspaces/datasets/*/write | EXCLUDED | Page states not a standalone primitive. |
| `az-privilege-escalation/az-ai-foundry-privesc.md#microsoftcognitiveservicesaccountswrite--account-config-tamper--uami-attach--re-enable-local-auth--open-network` | `Microsoft.CognitiveServices/accounts/write` — account config tamper + UAMI attach + re-enable local auth / open network | Microsoft.CognitiveServices/accounts/write | EXCLUDED | Account-level configuration and identity attach give no attacker-controlled code or request path running as the identity; local-auth and network changes are posture downgrades (key paths need listKeys). |
| `az-privilege-escalation/az-ai-foundry-privesc.md#references` | References |  | STRUCTURAL | section/how-to heading; no technique |

## az-privilege-escalation/az-ai-search-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-ai-search-privesc.md#az---ai-search-privesc` | Az - AI Search Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-ai-search-privesc.md#azure-ai-search` | Azure AI Search |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-ai-search-privesc.md#blind-source-replacement-with-microsoftsearchsearchservicesdatasourceswrite` | Blind source replacement with `Microsoft.Search/searchServices/dataSources/write` | Microsoft.Search/searchServices/dataSources/write | EXCLUDED | Data exfiltration through the Search identity; no identity gain for the source. |
| `az-privilege-escalation/az-ai-search-privesc.md#blind-indexer-creation-with-microsoftsearchsearchservicesindexerswrite` | Blind indexer creation with `Microsoft.Search/searchServices/indexers/write` | Microsoft.Search/searchServices/indexers/write | EXCLUDED | Data exfiltration through the Search identity; no identity gain for the source. |
| `az-privilege-escalation/az-ai-search-privesc.md#managed-identity-token-theft-with-microsoftsearchsearchservicesskillsetswrite` | Managed-identity token theft with `Microsoft.Search/searchServices/skillsets/write` | Microsoft.Search/searchServices/skillsets/write | EXCLUDED | NEEDS SCHEMA: Search write or admin-key authority alone does not prove a skill/indexer or debug session actually executed, delivered a usable token for an exact accepted audience, and enabled a newly permitted action for the named identity. |
| `az-privilege-escalation/az-ai-search-privesc.md#on-demand-skillset-detonation-with-microsoftsearchsearchservicesdebugsessionswrite--debugsessionsexecuteaction` | On-demand skillset detonation with `Microsoft.Search/searchServices/debugSessions/write` + `debugSessions/execute/action` | Microsoft.Search/searchServices/debugSessions/execute/action,Microsoft.Search/searchServices/debugSessions/write | EXCLUDED | NEEDS SCHEMA for exact debug-session execution, audience-bound usable token, and newly allowed action. |
| `az-privilege-escalation/az-ai-search-privesc.md#service-resource-tamper-with-microsoftsearchsearchserviceswrite` | Service-resource tamper with `Microsoft.Search/searchServices/write` | Microsoft.Search/searchServices/write | EXCLUDED | NEEDS SCHEMA: Attaching an assignable UAMI and modifying Search resources does not prove a skill executed, delivered its usable audience-bound token, and enabled a new action for that exact identity. |
| `az-privilege-escalation/az-ai-search-privesc.md#index-schema-poisoning--vectorizer-repoint-with-microsoftsearchsearchservicesindexeswrite` | Index schema poisoning / vectorizer repoint with `Microsoft.Search/searchServices/indexes/write` | Microsoft.Search/searchServices/indexes/write | EXCLUDED | NEEDS SCHEMA for exact vectorizer execution, audience-bound usable token, and newly allowed action. |
| `az-privilege-escalation/az-ai-search-privesc.md#enumeration-when-search-reads-are-denied` | Enumeration when Search reads are denied |  | EXCLUDED | Enumeration guidance only; no privilege gain. |

## az-privilege-escalation/az-analysis-services-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-analysis-services-privesc.md#az---analysis-services-privesc` | Az - Analysis Services Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-analysis-services-privesc.md#analysis-services` | Analysis Services |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-analysis-services-privesc.md#analysis-services-overview` | Analysis Services overview |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-analysis-services-privesc.md#server-admin-self-add--full-model-exfil-marquee` | Server-admin self-add → full model exfil (marquee) | Microsoft.AnalysisServices/servers/write | MAPPED | `azure-analysisservices-server-admin-write` |
| `az-privilege-escalation/az-analysis-services-privesc.md#firewall-widening--power-bi-exposure-reach-the-data-plane` | Firewall widening / Power BI exposure (reach the data plane) | Microsoft.AnalysisServices/servers/write | EXCLUDED | Network exposure only; data-plane access still needs server admin (azure-analysisservices-server-admin-write). |
| `az-privilege-escalation/az-analysis-services-privesc.md#references` | References |  | STRUCTURAL | section/how-to heading; no technique |

## az-privilege-escalation/az-api-center-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-api-center-privesc.md#az---api-center-privesc` | Az - API Center Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-api-center-privesc.md#api-center` | API Center |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-api-center-privesc.md#stored-credential-disclosure-getcredentials` | Stored-credential disclosure (`getCredentials`) | Microsoft.ApiCenter/services/workspaces/apis/versions/securityRequirements/getCredentials/action | EXCLUDED | Strict principal-boundary audit: The credential_stored_in_scope selector has no exact usable credential and identified target-principal evidence enforcement for this technique; a secret read or arbitrary configuration change alone is not an established principal escalation. |
| `az-privilege-escalation/az-api-center-privesc.md#internal-api-recon-data-reader` | Internal-API recon (Data Reader) |  | STRUCTURAL | pointer to post-exploitation page |
| `az-privilege-escalation/az-api-center-privesc.md#references` | References |  | STRUCTURAL | section/how-to heading; no technique |

## az-privilege-escalation/az-api-management-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-api-management-privesc.md#az---api-management-privesc` | Az - API Management Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-api-management-privesc.md#api-management` | API Management |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-api-management-privesc.md#microsoftapimanagementserviceuserstokenaction` | `Microsoft.ApiManagement/service/users/token/action` | Microsoft.ApiManagement/service/users/token/action | MAPPED | `azure-apim-developer-portal-sso-external-principal` requires the exact user, usable SSO URL, prior denial, and newly allowed portal action; historical broad entry remains excluded. |
| `az-privilege-escalation/az-api-management-privesc.md#microsoftapimanagementservicenamedvaluesread--microsoftapimanagementservicenamedvalueslistvalueaction` | `Microsoft.ApiManagement/service/namedValues/read` & `Microsoft.ApiManagement/service/namedValues/listValue/action` | Microsoft.ApiManagement/service/namedValues/listValue/action,Microsoft.ApiManagement/service/namedValues/read | EXCLUDED | Strict principal-boundary audit: The credential_stored_in_scope selector has no exact usable credential and identified target-principal evidence enforcement for this technique; a secret read or arbitrary configuration change alone is not an established principal escalation. |
| `az-privilege-escalation/az-api-management-privesc.md#microsoftapimanagementservicesubscriptionsread--microsoftapimanagementservicesubscriptionslistsecretsaction` | `Microsoft.ApiManagement/service/subscriptions/read` & `Microsoft.ApiManagement/service/subscriptions/listSecrets/action` | Microsoft.ApiManagement/service/subscriptions/listSecrets/action,Microsoft.ApiManagement/service/subscriptions/read | EXCLUDED | API access keys; data access only. |
| `az-privilege-escalation/az-api-management-privesc.md#microsoftapimanagementserviceapikeyslistsecretsaction` | `Microsoft.ApiManagement/service/apiKeys/listSecrets/action` | Microsoft.ApiManagement/service/apiKeys/listSecrets/action | EXCLUDED | Gateway runtime keys; configuration-dependent data access. |
| `az-privilege-escalation/az-api-management-privesc.md#microsoftapimanagementserviceworkspacestoolserverslistsecretsaction` | `Microsoft.ApiManagement/service/workspaces/toolServers/listSecrets/action` | Microsoft.ApiManagement/service/workspaces/toolServers/listSecrets/action | EXCLUDED | External credentials of unknown content. |
| `az-privilege-escalation/az-api-management-privesc.md#microsoftapimanagementserviceportalconfigslistdelegationsecretsaction-and-microsoftapimanagementserviceportalsettingslistsecretsaction` | `Microsoft.ApiManagement/service/portalConfigs/listDelegationSecrets/action` and `Microsoft.ApiManagement/service/portalSettings/listSecrets/action` | Microsoft.ApiManagement/service/portalConfigs/listDelegationSecrets/action,Microsoft.ApiManagement/service/portalSettings/listSecrets/action | EXCLUDED | NEEDS SCHEMA: delegation secrets can forge a portal user, but the exact forged subject, usable delegated credential, and newly permitted action are not verified. |
| `az-privilege-escalation/az-api-management-privesc.md#microsoftapimanagementserviceportalconfigslistmediacontentsecretsaction-and-microsoftapimanagementserviceportalsettingslistsecretsaction` | `Microsoft.ApiManagement/service/portalConfigs/listMediaContentSecrets/action` and `Microsoft.ApiManagement/service/portalSettings/listSecrets/action` | Microsoft.ApiManagement/service/portalConfigs/listMediaContentSecrets/action,Microsoft.ApiManagement/service/portalSettings/listSecrets/action | EXCLUDED | Portal media data access. |
| `az-privilege-escalation/az-api-management-privesc.md#microsoftapimanagementservicebackendsread` | `Microsoft.ApiManagement/service/backends/read` | Microsoft.ApiManagement/service/backends/read | EXCLUDED | Moved to post-exploitation; Stored header credentials of unknown content; data read. |
| `az-privilege-escalation/az-api-management-privesc.md#microsoftapimanagementservicebackendslistsecretsaction` | `Microsoft.ApiManagement/service/backends/listSecrets/action` | Microsoft.ApiManagement/service/backends/listSecrets/action,Microsoft.ApiManagement/service/workspaces/backends/listSecrets/action | EXCLUDED | NEEDS SCHEMA: APIM backend reads may expose downstream API credentials, but exact credential subject, usable secret, newly permitted action, and prior-absence proof are not verified. Named-value Entra paths are separately modelled. no Azure identity by themselves. |
| `az-privilege-escalation/az-api-management-privesc.md#microsoftapimanagementserviceauthorizationserverslistsecretsaction` | `Microsoft.ApiManagement/service/authorizationServers/listSecrets/action` | Microsoft.ApiManagement/service/authorizationServers/listSecrets/action | EXCLUDED | Strict principal-boundary audit: The credential_stored_in_scope selector has no exact usable credential and identified target-principal evidence enforcement for this technique; a secret read or arbitrary configuration change alone is not an established principal escalation. |
| `az-privilege-escalation/az-api-management-privesc.md#microsoftapimanagementserviceopenidconnectproviderslistsecretsaction` | `Microsoft.ApiManagement/service/openidConnectProviders/listSecrets/action` | Microsoft.ApiManagement/service/openidConnectProviders/listSecrets/action | EXCLUDED | Strict principal-boundary audit: The credential_stored_in_scope selector has no exact usable credential and identified target-principal evidence enforcement for this technique; a secret read or arbitrary configuration change alone is not an established principal escalation. |
| `az-privilege-escalation/az-api-management-privesc.md#microsoftapimanagementserviceidentityproviderslistsecretsaction` | `Microsoft.ApiManagement/service/identityProviders/listSecrets/action` | Microsoft.ApiManagement/service/identityProviders/listSecrets/action | EXCLUDED | Strict principal-boundary audit: The credential_stored_in_scope selector has no exact usable credential and identified target-principal evidence enforcement for this technique; a secret read or arbitrary configuration change alone is not an established principal escalation. |
| `az-privilege-escalation/az-api-management-privesc.md#microsoftapimanagementservicetenantlistsecretsaction` | `Microsoft.ApiManagement/service/tenant/listSecrets/action` | Microsoft.ApiManagement/service/tenant/listSecrets/action | EXCLUDED | APIM direct management API only. |
| `az-privilege-escalation/az-api-management-privesc.md#microsoftapimanagementservicegatewaysgeneratetokenaction` | `Microsoft.ApiManagement/service/gateways/generateToken/action` | Microsoft.ApiManagement/service/gateways/generateToken/action | EXCLUDED | Gateway configuration access only. |
| `az-privilege-escalation/az-api-management-privesc.md#policy-read-permissions` | Policy read permissions | Microsoft.ApiManagement/service/apis/operations/policies/read,Microsoft.ApiManagement/service/apis/policies/read,Microsoft.ApiManagement/service/policies/read,Microsoft.ApiManagement/service/products/policies/read | EXCLUDED | Moved to post-exploitation; Data read of embedded values. |
| `az-privilege-escalation/az-api-management-privesc.md#replace--with-one-of` | Replace <scope-path> with one of: |  | STRUCTURAL | code-comment pseudo-heading inside a policy example |
| `az-privilege-escalation/az-api-management-privesc.md#policiespolicy` | policies/policy |  | STRUCTURAL | code-comment pseudo-heading inside a policy example |
| `az-privilege-escalation/az-api-management-privesc.md#apispoliciespolicy` | apis/<api-id>/policies/policy |  | STRUCTURAL | code-comment pseudo-heading inside a policy example |
| `az-privilege-escalation/az-api-management-privesc.md#apisoperationspoliciespolicy` | apis/<api-id>/operations/<operation-id>/policies/policy |  | STRUCTURAL | code-comment pseudo-heading inside a policy example |
| `az-privilege-escalation/az-api-management-privesc.md#productspoliciespolicy` | products/<product-id>/policies/policy |  | STRUCTURAL | code-comment pseudo-heading inside a policy example |
| `az-privilege-escalation/az-api-management-privesc.md#microsoftapimanagementservicepolicieswrite-or-microsoftapimanagementserviceapispolicieswrite` | `Microsoft.ApiManagement/service/policies/write` or `Microsoft.ApiManagement/service/apis/policies/write` | Microsoft.ApiManagement/service/apis/policies/write,Microsoft.ApiManagement/service/policies/write | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-api-management-privesc.md#microsoftapimanagementserviceapispolicieswrite--steal-the-apim-managed-identity-token` |
| `az-privilege-escalation/az-api-management-privesc.md#jwt-validation-misconfiguration` | JWT Validation Misconfiguration | Microsoft.ApiManagement/service/apis/policies/write,Microsoft.ApiManagement/service/policies/write | EXCLUDED | Application-level misconfiguration; not an RBAC edge. |
| `az-privilege-escalation/az-api-management-privesc.md#microsoftapimanagementserviceapplynetworkconfigurationupdatesaction` | `Microsoft.ApiManagement/service/applynetworkconfigurationupdates/action` | Microsoft.ApiManagement/service/applynetworkconfigurationupdates/action,Microsoft.ApiManagement/service/write | EXCLUDED | Moved to post-exploitation; Network exposure change only. |
| `az-privilege-escalation/az-api-management-privesc.md#microsoftapimanagementservicebackendswrite` | `Microsoft.ApiManagement/service/backends/write` | Microsoft.ApiManagement/service/backends/read,Microsoft.ApiManagement/service/backends/write | EXCLUDED | Traffic and Named Value capture of unknown content; no modelable identity edge. |
| `az-privilege-escalation/az-api-management-privesc.md#microsoftapimanagementserviceapispolicieswrite--steal-the-apim-managed-identity-token` | `Microsoft.ApiManagement/service/apis/policies/write` — steal the APIM managed-identity token | Microsoft.ApiManagement/service/*,Microsoft.ApiManagement/service/apis/policies/write | MAPPED | `azure-apim-policy-write-managed-identity-token` |
| `az-privilege-escalation/az-api-management-privesc.md#microsoftapimanagementserviceapispolicieswrite--ssrf--internal--imds-pivot-via-` | `Microsoft.ApiManagement/service/apis/policies/write` — SSRF / internal & IMDS pivot via `<send-request>` | Microsoft.ApiManagement/service/apis/policies/write | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-api-management-privesc.md#microsoftapimanagementserviceapispolicieswrite--steal-the-apim-managed-identity-token` |
| `az-privilege-escalation/az-api-management-privesc.md#references` | References |  | STRUCTURAL | references/enumeration |

## az-privilege-escalation/az-app-configuration-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-app-configuration-privesc.md#az---app-configuration-privesc` | Az - App Configuration Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-app-configuration-privesc.md#app-configuration` | App Configuration |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-app-configuration-privesc.md#microsoftappconfigurationconfigurationstoreslistkeysaction` | `Microsoft.AppConfiguration/configurationStores/ListKeys/action` | Microsoft.AppConfiguration/configurationStores/ListKeys/action | EXCLUDED | Configuration data read; Key Vault references are not resolved. |
| `az-privilege-escalation/az-app-configuration-privesc.md#read-one-key-value` | Read one key-value |  | STRUCTURAL | section grouping heading for the two read sub-techniques (both excluded) |
| `az-privilege-escalation/az-app-configuration-privesc.md#microsoftappconfigurationconfigurationstoreslistkeyvalueaction` | Microsoft.AppConfiguration/configurationStores/ListKeyValue/action | Microsoft.AppConfiguration/configurationStores/ListKeyValue/action | EXCLUDED | Moved to post-exploitation; Data read of configuration values; Key Vault references resolve only with the consumer's identity, so no Azure identity is gained by the source. |
| `az-privilege-escalation/az-app-configuration-privesc.md#microsoftappconfigurationconfigurationstoreskeyvaluesread` | Microsoft.AppConfiguration/configurationStores/keyValues/read | Microsoft.AppConfiguration/configurationStores/keyValues/read | EXCLUDED | Moved to post-exploitation; Data read; no identity gained. |
| `az-privilege-escalation/az-app-configuration-privesc.md#microsoftappconfigurationconfigurationstoreskeyvalueswrite` | `Microsoft.AppConfiguration/configurationStores/keyValues/write` | Microsoft.AppConfiguration/configurationStores/keyValues/write | EXCLUDED | `azure-appconfig-keyvalue-poisoning-consumer` NEEDS SCHEMA: exact written object or message, consumer binding and trigger, observed execution, and a newly obtained identity token or action are unverified. |
| `az-privilege-escalation/az-app-configuration-privesc.md#microsoftappconfigurationconfigurationstoresregeneratekeyaction` | `Microsoft.AppConfiguration/configurationStores/RegenerateKey/action` | Microsoft.AppConfiguration/configurationStores/RegenerateKey/action | EXCLUDED | Rotate-and-capture of store access keys yields store data-plane read/write only (config poisoning whose effect depends on consumers), no Azure identity. |
| `az-privilege-escalation/az-app-configuration-privesc.md#weaken-store-posture-with-configurationstoreswrite` | Weaken store posture with `configurationStores/write` |  | EXCLUDED | Re-enables local auth / public network; posture downgrade, no identity. |

## az-privilege-escalation/az-app-services-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-app-services-privesc.md#az---app-services-privesc` | Az - App Services Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-app-services-privesc.md#app-services` | App Services |  | STRUCTURAL | section grouping heading; techniques are its subsections |
| `az-privilege-escalation/az-app-services-privesc.md#microsoftwebsitespublishaction-and-microsoftwebsitesslotspublishaction` | `Microsoft.Web/sites/publish/action` and `Microsoft.Web/sites/slots/publish/action` | Microsoft.Web/sites/publish/action,Microsoft.Web/sites/slots/publish/action | MAPPED | `azure-appservice-kudu-publish-action` |
| `az-privilege-escalation/az-app-services-privesc.md#obtaining-scm-credentials--enabling-basic-authentication` | Obtaining SCM Credentials & Enabling Basic Authentication | Microsoft.Web/sites/publishxml/action | MAPPED | `azure-appservice-publishing-credentials-enable-basic-auth` |
| `az-privilege-escalation/az-app-services-privesc.md#publish-code-using-scm-credentials` | Publish code using SCM credentials |  | MAPPED | `azure-appservice-publishing-credentials-basic-auth-enabled` |
| `az-privilege-escalation/az-app-services-privesc.md#webjobs-microsoftwebsitespublishaction--scm-credentials` | Webjobs: Microsoft.Web/sites/publish/Action \| SCM credentials | Microsoft.Web/sites/publish/Action,Microsoft.Web/sites/publish/action | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-app-services-privesc.md#microsoftwebsitespublishaction-and-microsoftwebsitesslotspublishaction` |
| `az-privilege-escalation/az-app-services-privesc.md#start-existing-webjobs` | Start existing WebJobs | Microsoft.Web/sites/continuouswebjobs/start/action,Microsoft.Web/sites/triggeredwebjobs/run/action | EXCLUDED | Runs existing code without attacker input; impact is behaviour-dependent, not an identity gain. |
| `az-privilege-escalation/az-app-services-privesc.md#microsoftwebsiteswrite-microsoftwebsitesread-microsoftmanagedidentityuserassignedidentitiesassignaction` | Microsoft.Web/sites/write, Microsoft.Web/sites/read, Microsoft.ManagedIdentity/userAssignedIdentities/assign/action | Microsoft.ManagedIdentity/userAssignedIdentities/assign/action,Microsoft.Web/sites/read,Microsoft.Web/sites/write | MAPPED | `azure-appservice-assign-user-assigned-identity` |
| `az-privilege-escalation/az-app-services-privesc.md#microsoftwebsitesconfiglistaction` | Microsoft.Web/sites/config/list/action | Microsoft.Web/sites/config/list/action | EXCLUDED | Data exposure; publishing-credential path modelled in app_services.yaml. |
| `az-privilege-escalation/az-app-services-privesc.md#microsoftwebsiteshybridconnectionnamespacesrelayslistkeysaction` | `Microsoft.Web/sites/hybridConnectionNamespaces/relays/listKeys/action` | Microsoft.Web/sites/hybridConnectionNamespaces/relays/listKeys/action | EXCLUDED | NEEDS SCHEMA: a Relay sender key can authenticate a bounded Relay sender identity, but the exact rule, usable key, allowed send operation, and prior-absence proof are not verified. |
| `az-privilege-escalation/az-app-services-privesc.md#microsoftwebsitesconfigsnapshotslistsecretsaction-microsoftwebsitesslotsconfigsnapshotslistsecretsaction` | `Microsoft.Web/sites/config/snapshots/listsecrets/action`, `Microsoft.Web/sites/slots/config/snapshots/listsecrets/action` | Microsoft.Web/sites/config/snapshots/listsecrets/action,Microsoft.Web/sites/slots/config/snapshots/listsecrets/action | EXCLUDED | Historical settings data exposure; content-dependent. |
| `az-privilege-escalation/az-app-services-privesc.md#read-configured-third-party-credentials` | Read Configured Third Party Credentials | Microsoft.Web/sourcecontrols | EXCLUDED | NEEDS SCHEMA: returned GitHub or Bitbucket tokens can confer external repository authority, but the target account, usable token, granted repository permissions, and prior-absence proof are not collected. |
| `az-privilege-escalation/az-app-services-privesc.md#update-app-code-from-the-source` | Update App Code from the source | Microsoft.Web/sites/publishxml/action,Microsoft.Web/sites/sourcecontrols/read | EXCLUDED | Requires compromise of an external repository; RBAC-derived SCM credential path is modelled in app_services.yaml. |
| `az-privilege-escalation/az-app-services-privesc.md#microsoftwebsitessourcecontrolswrite-and-microsoftwebsitesslotssourcecontrolswrite` | `Microsoft.Web/sites/sourcecontrols/write` and `Microsoft.Web/sites/slots/sourcecontrols/write` | Microsoft.Web/sites/slots/sourcecontrols/write,Microsoft.Web/sites/sourcecontrols/write | MAPPED | `azure-appservice-sourcecontrols-write` |
| `az-privilege-escalation/az-app-services-privesc.md#microsoftwebsitessitecontainerswrite-and-microsoftwebsitesslotssitecontainerswrite` | `Microsoft.Web/sites/sitecontainers/write` and `Microsoft.Web/sites/slots/sitecontainers/write` | Microsoft.Web/sites/sitecontainers/write,Microsoft.Web/sites/slots/sitecontainers/write | MAPPED | `azure-appservice-sitecontainers-write` |
| `az-privilege-escalation/az-app-services-privesc.md#microsoftwebsitesconfigwrite` | `Microsoft.Web/sites/config/write` | Microsoft.Web/sites/config/write | MAPPED | `azure-appservice-config-write` |
| `az-privilege-escalation/az-app-services-privesc.md#microsoftwebsitesconfigwrite-microsoftwebsitesconfigread-microsoftwebsitesconfiglistaction-microsoftwebsitesread` | `Microsoft.Web/sites/config/Write`, `Microsoft.Web/sites/config/Read`, `Microsoft.Web/sites/config/list/Action`, `Microsoft.Web/sites/Read` | Microsoft.Web/sites/Read,Microsoft.Web/sites/config/Read,Microsoft.Web/sites/config/Write,Microsoft.Web/sites/config/list/Action,Microsoft.Web/sites/config/write | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-app-services-privesc.md#microsoftwebsitesconfigwrite` |
| `az-privilege-escalation/az-app-services-privesc.md#code-injection-via-microsoftwebsites-write-operations` | Code injection via `Microsoft.Web/sites/*` write operations | Microsoft.Web/sites/* | STRUCTURAL | section grouping heading; techniques are its subsections |
| `az-privilege-escalation/az-app-services-privesc.md#rce-via-app-settings--environment-variables-microsoftwebsitesconfigwrite` | RCE via app-settings / environment variables (`Microsoft.Web/sites/config/write`) | Microsoft.Web/sites/*,Microsoft.Web/sites/config/write | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-app-services-privesc.md#microsoftwebsitesconfigwrite` |
| `az-privilege-escalation/az-app-services-privesc.md#microsoftwebsitessiteextensionswrite--attacker-nuget-site-extension` | `Microsoft.Web/sites/siteextensions/write` — attacker NuGet site extension | Microsoft.Web/sites/siteextensions/write | MAPPED | `azure-appservice-siteextensions-write` |
| `az-privilege-escalation/az-app-services-privesc.md#microsoftwebsitesextensionswrite--onedeploy-zip-replacement` | `Microsoft.Web/sites/extensions/write` — OneDeploy ZIP replacement | Microsoft.Web/sites/extensions/write | MAPPED | `azure-appservice-onedeploy-extensions-write` |
| `az-privilege-escalation/az-app-services-privesc.md#microsoftwebsitesrestorefrombackupblobaction--restore-an-attacker-backup` | `Microsoft.Web/sites/restoreFromBackupBlob/action` — restore an attacker backup | Microsoft.Web/sites/restoreFromBackupBlob/action | MAPPED | `azure-appservice-restore-from-backup-blob` |
| `az-privilege-escalation/az-app-services-privesc.md#microsoftwebsitesslotsconfigwrite--recycle-a-deployment-slot-into-attacker-code` | `Microsoft.Web/sites/slots/config/write` — recycle a deployment slot into attacker code | Microsoft.Web/sites/slots/config/write | MAPPED | `azure-appservice-slot-code-execution` |
| `az-privilege-escalation/az-app-services-privesc.md#storage-backed-external-function-packages` | Storage-backed external Function packages |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-functions-app-privesc.md#storage-backed-deployment-content` |
| `az-privilege-escalation/az-app-services-privesc.md#replace-a-functions-code-with-microsoftwebsitesfunctionswrite` | Replace a Function's code with `Microsoft.Web/sites/functions/write` | Microsoft.Web/sites/functions/write | MAPPED | `azure-functions-functions-write` |
| `az-privilege-escalation/az-app-services-privesc.md#replace-function-code-on-its-azure-files-content-share-fileswrite--writefilebackupsemantics` | Replace Function code on its Azure Files content share (`files/write` + `writeFileBackupSemantics`) | Microsoft.Storage/storageAccounts/fileServices/fileshares/files/write,Microsoft.Storage/storageAccounts/fileServices/writeFileBackupSemantics/action | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-functions-app-privesc.md#storage-backed-deployment-content` |
| `az-privilege-escalation/az-app-services-privesc.md#microsoftwebsitesslotsswapaction-promote-staged-code--steal-production-sticky-secrets` | `Microsoft.Web/sites/slotsswap/action` (promote staged code / steal production sticky secrets) | Microsoft.Web/sites/applySlotConfig/action,Microsoft.Web/sites/slotsswap/action | MAPPED | `azure-appservice-slot-swap-promote-code` |
| `az-privilege-escalation/az-app-services-privesc.md#microsoftwebsitesbackupaction-backup-exfiltration-to-attacker-storage` | `Microsoft.Web/sites/backup/action` (backup exfiltration to attacker storage) | Microsoft.Web/sites/backup/action,Microsoft.Web/sites/config/write | EXCLUDED | Data exfiltration of site content/secrets; no identity gained directly. |
| `az-privilege-escalation/az-app-services-privesc.md#microsoftwebsitesnetworkconfigwrite-vnet-integration-for-an-internal-pivot` | `Microsoft.Web/sites/networkConfig/write` (VNet integration for an internal pivot) | Microsoft.Network/virtualNetworks/subnets/join/action,Microsoft.Web/sites/networkConfig/write | EXCLUDED | Network pivot; needs code execution modelled elsewhere. |
| `az-privilege-escalation/az-app-services-privesc.md#kudu-process-memory-dump-harvest-in-memory-mi-tokens--decrypted-secrets` | Kudu process memory dump (harvest in-memory MI tokens / decrypted secrets) | Microsoft.Web/sites/instances/processes/read,Microsoft.Web/sites/publish/action | EXCLUDED | NEEDS SCHEMA: Process-dump permission does not prove the exact process contains a live usable managed-identity token, that the dump was obtained, or which identity and newly allowed action it authenticates. |
| `az-privilege-escalation/az-app-services-privesc.md#easy-auth-secret-theft--authentication-bypass` | Easy Auth secret theft + authentication bypass | Microsoft.Web/sites/config/list/action,Microsoft.Web/sites/config/write | EXCLUDED | Strict principal-boundary audit: The credential_stored_in_scope selector has no exact usable credential and identified target-principal evidence enforcement for this technique; a secret read or arbitrary configuration change alone is not an established principal escalation. |
| `az-privilege-escalation/az-app-services-privesc.md#remove-accessip-restrictions-to-expose-a-network-restricted-app` | Remove access/IP restrictions to expose a network-restricted app | Microsoft.Web/sites/config/write | EXCLUDED | Network exposure only. |
| `az-privilege-escalation/az-app-services-privesc.md#microsoftwebsiteshybridconnectionnamespacesrelayswrite-attacker-relay-outbound-pivot` | `Microsoft.Web/sites/hybridConnectionNamespaces/relays/write` (attacker-relay outbound pivot) | Microsoft.Web/sites/hybridConnectionNamespaces/relays/write | EXCLUDED | Outbound network pivot; no identity. |
| `az-privilege-escalation/az-app-services-privesc.md#app-service-domain-transfer-code-via-hidden-wildcard-operation` | App Service Domain transfer code via hidden wildcard operation | Microsoft.DomainRegistration/*,Microsoft.DomainRegistration/domains/*,Microsoft.DomainRegistration/domains/transferOut/write | EXCLUDED | Domain hijack (DNS / phishing impact); no Azure identity. |
| `az-privilege-escalation/az-app-services-privesc.md#references` | References |  | STRUCTURAL | references/enumeration |

## az-privilege-escalation/az-arc-enabled-servers-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-arc-enabled-servers-privesc.md#az---arc-enabled-servers-privesc` | Az - Arc-enabled Servers Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-arc-enabled-servers-privesc.md#azure-arc-enabled-servers` | Azure Arc-enabled Servers |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-arc-enabled-servers-privesc.md#arc-enabled-servers-overview` | Arc-enabled servers overview |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-arc-enabled-servers-privesc.md#rce-via-arc-run-command` | RCE via Arc Run Command | Microsoft.HybridCompute/machines/runCommands/write | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputevirtualmachinesruncommandswrite` |
| `az-privilege-escalation/az-arc-enabled-servers-privesc.md#rce--persistence-via-vm-extensions-custom-script` | RCE + persistence via VM extensions (Custom Script) | Microsoft.HybridCompute/machines/read | MAPPED | `azure-arc-machine-extensions-write` |
| `az-privilege-escalation/az-arc-enabled-servers-privesc.md#attach-a-privileged-managed-identity-machine-write` | Attach a privileged managed identity (machine write) | Microsoft.HybridCompute/machines/write | EXCLUDED | Arc-enabled servers support only a system-assigned identity (no user-assigned attach); machines/write alone gives no code execution. |
| `az-privilege-escalation/az-arc-enabled-servers-privesc.md#managed-identity-token-theft-via-himds-on-prem--azure-pivot` | Managed-identity token theft via HIMDS (on-prem → Azure pivot) |  | EXCLUDED | On-box step; the reaching RCE paths are azure-arc-machine-extensions-write, azure-arc-machine-runcommands-write and azure-arc-hybrid-connectivity-entra-ssh. |
| `az-privilege-escalation/az-arc-enabled-servers-privesc.md#sshrdp-to-arc-machines-via-hybrid-connectivity` | SSH/RDP to Arc machines via Hybrid Connectivity | Microsoft.HybridConnectivity/endpoints/listCredentials/action | MAPPED | `azure-arc-hybrid-connectivity-entra-ssh` |
| `az-privilege-escalation/az-arc-enabled-servers-privesc.md#license--license-profile-writes-billing-abuse` | License / license-profile writes (billing abuse) | Microsoft.HybridCompute/licenses/write,Microsoft.HybridCompute/machines/licenseProfiles/write | EXCLUDED | Billing abuse; no identity. |
| `az-privilege-escalation/az-arc-enabled-servers-privesc.md#references` | References |  | STRUCTURAL | references/enumeration |

## az-privilege-escalation/az-arc-resource-bridge-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-arc-resource-bridge-privesc.md#az---arc-resource-bridge-privesc` | Az - Arc Resource Bridge Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-arc-resource-bridge-privesc.md#azure-arc-resource-bridge` | Azure Arc Resource Bridge |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-arc-resource-bridge-privesc.md#export-customer-kubeconfig-and-ssh-credentials` | Export customer kubeconfig and SSH credentials | Microsoft.ResourceConnector/appliances/listKeys/action | MAPPED | `azure-arc-resource-bridge-credential-export` |
| `az-privilege-escalation/az-arc-resource-bridge-privesc.md#export-partner-kubeconfig-and-hybrid-connection-listener-token` | Export partner kubeconfig and hybrid-connection listener token | Microsoft.ResourceConnector/appliances/listClusterUserCredential/action | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-arc-resource-bridge-privesc.md#export-customer-kubeconfig-and-ssh-credentials` |
| `az-privilege-escalation/az-arc-resource-bridge-privesc.md#built-in-role-exposure` | Built-in role exposure |  | EXCLUDED | Role inventory guidance; no separate primitive. |
| `az-privilege-escalation/az-arc-resource-bridge-privesc.md#references` | References |  | STRUCTURAL | references/enumeration |

## az-privilege-escalation/az-arm-deployment-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-arm-deployment-privesc.md#az---arm-deployment-privesc` | Az - ARM Deployment Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-arm-deployment-privesc.md#arm-templates--deployments` | ARM Templates / Deployments |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-arm-deployment-privesc.md#microsoftresourcesdeploymentscriptswrite` | `Microsoft.Resources/deploymentScripts/write` | Microsoft.Resources/deploymentScripts/write;Microsoft.ManagedIdentity/userAssignedIdentities/assign/action;Microsoft.ContainerInstance/containerGroups/read;Microsoft.ContainerInstance/containerGroups/write;Microsoft.Storage/storageAccounts/read;Microsoft.Storage/storageAccounts/write;Microsoft.Storage/storageAccounts/listKeys/action | MAPPED | `azure-arm-deploymentscript-with-user-assigned-identity` |
| `az-privilege-escalation/az-arm-deployment-privesc.md#minimum-permissions` | Minimum permissions |  | SUBSECTION | of #microsoftresourcesdeploymentscriptswrite: azure-arm-deploymentscript-with-user-assigned-identity |
| `az-privilege-escalation/az-arm-deployment-privesc.md#find-a-candidate-or-use-no-list-fallback` | Find a candidate or use no-list fallback |  | SUBSECTION | of #microsoftresourcesdeploymentscriptswrite: azure-arm-deploymentscript-with-user-assigned-identity |
| `az-privilege-escalation/az-arm-deployment-privesc.md#bash--azure-cli` | Bash / Azure CLI |  | SUBSECTION | of #microsoftresourcesdeploymentscriptswrite: azure-arm-deploymentscript-with-user-assigned-identity |
| `az-privilege-escalation/az-arm-deployment-privesc.md#powershell` | PowerShell |  | SUBSECTION | of #microsoftresourcesdeploymentscriptswrite: azure-arm-deploymentscript-with-user-assigned-identity |
| `az-privilege-escalation/az-arm-deployment-privesc.md#boundaries` | Boundaries |  | SUBSECTION | of #microsoftresourcesdeploymentscriptswrite: azure-arm-deploymentscript-with-user-assigned-identity |
| `az-privilege-escalation/az-arm-deployment-privesc.md#read-declared-outputs-and-execution-logs` | Read declared outputs and execution logs |  | EXCLUDED | Data read of outputs/logs; content-dependent exposure. |
| `az-privilege-escalation/az-arm-deployment-privesc.md#bash--azure-cli-1` | Bash / Azure CLI |  | SUBSECTION | of #read-declared-outputs-and-execution-logs: EXCLUDED (_excluded_rbac.yaml) |
| `az-privilege-escalation/az-arm-deployment-privesc.md#powershell-1` | PowerShell |  | SUBSECTION | of #read-declared-outputs-and-execution-logs: EXCLUDED (_excluded_rbac.yaml) |

## az-privilege-escalation/az-arm-template-spec-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-arm-template-spec-privesc.md#az---arm-template-spec-privesc` | Az - ARM Template Spec Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-arm-template-spec-privesc.md#arm-templates--deployments` | ARM Templates / Deployments |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-arm-template-spec-privesc.md#microsoftresourcestemplatespecsversionswrite` | `Microsoft.Resources/templateSpecs/versions/write` | Microsoft.Resources/templateSpecs/versions/write | EXCLUDED | Three template-spec deployer variants remain excluded: the future deploying principal, successful deployment, and captured new credential or permission are not established by version write permission. |
| `az-privilege-escalation/az-arm-template-spec-privesc.md#related-actions` | Related actions |  | EXCLUDED | Read/delete are exposure/DoS; deploymentStacks write is not a standalone escalation per the page. |

## az-privilege-escalation/az-attestation-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-attestation-privesc.md#az---attestation-privesc` | Az - Attestation Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-attestation-privesc.md#azure-attestation` | Azure Attestation |  | STRUCTURAL | pointer to post-exploitation page |
| `az-privilege-escalation/az-attestation-privesc.md#microsoftattestationattestationprovidersattestationwrite` | `Microsoft.Attestation/attestationProviders/attestation/write` | Microsoft.Attestation/attestationProviders/attestation/write | STRUCTURAL | pointer to post-exploitation page |
| `az-privilege-escalation/az-attestation-privesc.md#signed-provider-boundary` | Signed-provider boundary |  | STRUCTURAL | pointer to post-exploitation page |
| `az-privilege-escalation/az-attestation-privesc.md#references` | References |  | STRUCTURAL | pointer to post-exploitation page |

## az-post-exploitation/az-attestation-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-attestation-post-exploitation.md#az---attestation-post-exploitation` | Az - Attestation Post Exploitation |  | STRUCTURAL | post-exploitation page title |
| `az-post-exploitation/az-attestation-post-exploitation.md#azure-attestation` | Azure Attestation |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-post-exploitation/az-attestation-post-exploitation.md#microsoftattestationattestationprovidersattestationwrite` | `Microsoft.Attestation/attestationProviders/attestation/write` | Microsoft.Attestation/attestationProviders/attestation/write | EXCLUDED | Subverts trust decisions of relying workloads; no direct identity gain modelable from RBAC. |
| `az-post-exploitation/az-attestation-post-exploitation.md#signed-provider-boundary` | Signed-provider boundary |  | SUBSECTION | of #microsoftattestationattestationprovidersattestationwrite: EXCLUDED Subverts trust decisions of relying workloads; no direct identity gain modelable from RBAC. |
| `az-post-exploitation/az-attestation-post-exploitation.md#references` | References |  | STRUCTURAL | section/how-to heading; no technique |

## az-privilege-escalation/az-authorization-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-authorization-privesc.md#az---azure-iam-privesc-authorization` | Az - Azure IAM Privesc (Authorization) |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-authorization-privesc.md#entra-id-azuread--azure-iam` | Entra ID (AzureAD) & Azure IAM |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-authorization-privesc.md#azure-iam` | Azure IAM |  | STRUCTURAL | section grouping heading |
| `az-privilege-escalation/az-authorization-privesc.md#microsoftauthorizationroleassignmentswrite` | Microsoft.Authorization/roleAssignments/write | Microsoft.Authorization/roleAssignments/write | EXCLUDED | NEEDS SCHEMA: roleAssignments/write may be ABAC-limited to specific roles and principal types. Before claiming Owner, validate the exact source assignment condition, target scope, assignee, successful Owner grant, and newly effective permissions. |
| `az-privilege-escalation/az-authorization-privesc.md#microsoftauthorizationroledefinitionswrite` | Microsoft.Authorization/roleDefinitions/write | Microsoft.Authorization/roleDefinitions/write | EXCLUDED | NEEDS SCHEMA: roleDefinitions/write at one scope does not prove write authority over every custom-role AssignableScope, successful role update, or a new effective action through an exact existing source assignment. |
| `az-privilege-escalation/az-authorization-privesc.md#abac-constrained-delegation-bypass-via-custom-role-indirection` | ABAC-constrained delegation bypass via custom-role indirection | Microsoft.Authorization/roleAssignments/write;Microsoft.Authorization/roleDefinitions/write | EXCLUDED | NEEDS SCHEMA: roleAssignments/write plus roleDefinitions/write cannot prove a denylist-only delegation, matching scope, accepted custom role creation/assignment, and subsequent Owner grant without typed condition and outcome proof. |
| `az-privilege-escalation/az-authorization-privesc.md#permission-first-role-discovery` | Permission-first role discovery |  | EXCLUDED | Enumeration guidance only; no privilege gain. |
| `az-privilege-escalation/az-authorization-privesc.md#microsoftauthorizationelevateaccessaction` | Microsoft.Authorization/elevateAccess/action | Global Administrator | MAPPED | `azure-authorization-elevateaccess-global-admin` |
| `az-privilege-escalation/az-authorization-privesc.md#microsoftmanagedidentityuserassignedidentitiesfederatedidentitycredentialswrite` | Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write | Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write | MAPPED | `azure-managedidentity-federated-credential-write` |
| `az-privilege-escalation/az-authorization-privesc.md#microsoftauthorizationpolicyassignmentswrite--microsoftauthorizationpolicyassignmentsdelete` | Microsoft.Authorization/policyAssignments/write \| Microsoft.Authorization/policyAssignments/delete | Microsoft.Authorization/policyAssignments/write;Microsoft.ManagedIdentity/userAssignedIdentities/assign/action;Microsoft.Authorization/policyDefinitions/write | MAPPED | `azure-policy-assignment-write-user-assigned-identity` |
| `az-privilege-escalation/az-authorization-privesc.md#microsoftauthorizationpolicydefinitionswrite` | Microsoft.Authorization/policyDefinitions/write | Microsoft.Authorization/policyDefinitions/write;Microsoft.Authorization/policySetDefinitions/write | EXCLUDED | NEEDS SCHEMA: Policy definition write alone does not prove an exact definition-to-assignment-to-MI join, remediation execution, or an observed newly authorized action as that MI. |
| `az-privilege-escalation/az-authorization-privesc.md#microsoftmanagementmanagementgroupswrite` | Microsoft.Management/managementGroups/write | Microsoft.Management/managementGroups/write | EXCLUDED | Creating or re-parenting management groups changes inherited policy/RBAC, but per Microsoft docs moving an MG/subscription also requires Owner-equivalent (roleAssignments/write) on the child, which already yields scope ownership; no additional edge. |
| `az-privilege-escalation/az-authorization-privesc.md#microsoftmanagementmanagementgroupssubscriptionswrite` | Microsoft.Management/managementGroups/subscriptions/write | Microsoft.Management/managementGroups/subscriptions/write | EXCLUDED | Subscription move requires Owner on the subscription (roleAssignments/write) plus MG write on source/target parents; the resulting gain is already covered by azure-authorization-roleassignments-write. Main effect is policy evasion. |
| `az-privilege-escalation/az-authorization-privesc.md#references` | References |  | STRUCTURAL | references |

## az-privilege-escalation/az-automation-accounts-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-automation-accounts-privesc.md#az---azure-automation-accounts-privesc` | Az - Azure Automation Accounts Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-automation-accounts-privesc.md#automation-accounts` | Automation Accounts |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-automation-accounts-privesc.md#azure-automation-accounts` | Azure Automation Accounts |  | STRUCTURAL | section grouping heading |
| `az-privilege-escalation/az-automation-accounts-privesc.md#microsoftautomationautomationaccountslistkeysaction` | `Microsoft.Automation/automationAccounts/listKeys/action` | Microsoft.Automation/automationAccounts/listKeys/action | EXCLUDED | NEEDS SCHEMA: Automation account key access alone does not prove a rogue worker registered, received an exact job, executed under its identity, or exposed a usable token/new action. |
| `az-privilege-escalation/az-automation-accounts-privesc.md#microsoftautomationautomationaccountsjobsstreamsread` | `Microsoft.Automation/automationAccounts/jobs/streams/read` | Microsoft.Automation/automationAccounts/jobs/streams/read | EXCLUDED | Moved to post-exploitation; Data read of historical job output; any secret exposure is content-dependent (Exposure/Least Privilege). |
| `az-privilege-escalation/az-automation-accounts-privesc.md#microsoftautomationautomationaccountsvariablesread` | `Microsoft.Automation/automationAccounts/variables/read` | Microsoft.Automation/automationAccounts/variables/read | EXCLUDED | Moved to post-exploitation; Data read of unencrypted variables only (encrypted values return null); content-dependent exposure. |
| `az-privilege-escalation/az-automation-accounts-privesc.md#hybrid-workers-group` | Hybrid Workers Group | Microsoft.Automation/automationAccounts/runbooks/draft/write;Microsoft.Automation/automationAccounts/runbooks/draft/content/write;Microsoft.Automation/automationAccounts/runbooks/publish/action;Microsoft.Automation/automationAccounts/jobs/write;Microsoft.Automation/automationAccounts/runbooks/write;Microsoft.Automation/automationAccounts/runbooks/draft/testJob/write | MAPPED | `azure-automation-runbook-hybrid-worker` |
| `az-privilege-escalation/az-automation-accounts-privesc.md#microsoftautomationautomationaccountsjobswrite-microsoftautomationautomationaccountsrunbooksdraftwrite-microsoftautomationautomationaccountsrunbooksdraftcontentwrite-microsoftautomationautomationaccountsjobsoutputread-microsoftautomationautomationaccountsrunbookspublishaction-microsoftresourcessubscriptionsresourcegroupsread-microsoftautomationautomationaccountsrunbookswrite` | `Microsoft.Automation/automationAccounts/jobs/write`, `Microsoft.Automation/automationAccounts/runbooks/draft/write`, `Microsoft.Automation/automationAccounts/runbooks/draft/content/write`, `Microsoft.Automation/automationAccounts/jobs/output/read`, `Microsoft.Automation/automationAccounts/runbooks/publish/action` (`Microsoft.Resources/subscriptions/resourcegroups/read`, `Microsoft.Automation/automationAccounts/runbooks/write`) | Microsoft.Automation/automationAccounts/runbooks/draft/write;Microsoft.Automation/automationAccounts/runbooks/draft/content/write;Microsoft.Automation/automationAccounts/runbooks/publish/action;Microsoft.Automation/automationAccounts/jobs/write;Microsoft.Automation/automationAccounts/runbooks/write;Microsoft.Automation/automationAccounts/runbooks/draft/testJob/write | MAPPED | `azure-automation-runbook-author-and-run` |
| `az-privilege-escalation/az-automation-accounts-privesc.md#microsoftautomationautomationaccountswrite-microsoftmanagedidentityuserassignedidentitiesassignaction` | `Microsoft.Automation/automationAccounts/write`, `Microsoft.ManagedIdentity/userAssignedIdentities/assign/action` | Microsoft.ManagedIdentity/userAssignedIdentities/assign/action;Microsoft.Automation/automationAccounts/write;Microsoft.Automation/automationAccounts/runbooks/write;Microsoft.Automation/automationAccounts/runbooks/draft/content/write;Microsoft.Automation/automationAccounts/runbooks/publish/action;Microsoft.Automation/automationAccounts/jobs/write;Microsoft.Automation/automationAccounts/runbooks/draft/write;Microsoft.Automation/automationAccounts/runbooks/draft/testJob/write | MAPPED | `azure-automation-assign-user-assigned-identity` |
| `az-privilege-escalation/az-automation-accounts-privesc.md#microsoftautomationautomationaccountsscheduleswrite-microsoftautomationautomationaccountsjobscheduleswrite` | `Microsoft.Automation/automationAccounts/schedules/write`, `Microsoft.Automation/automationAccounts/jobSchedules/write` | Microsoft.Automation/automationAccounts/schedules/write;Microsoft.Automation/automationAccounts/jobSchedules/write | EXCLUDED | NEEDS SCHEMA for exact runbook/schedule binding and observed execution under a named identity. |
| `az-privilege-escalation/az-automation-accounts-privesc.md#microsoftautomationautomationaccountswebhooks--microsoftautomationautomationaccountsrunbooksread` | `Microsoft.Automation/automationAccounts/webhooks/*` + `Microsoft.Automation/automationAccounts/runbooks/read` | Microsoft.Automation/automationAccounts/webhooks/*;Microsoft.Automation/automationAccounts/runbooks/read | EXCLUDED | NEEDS SCHEMA for exact webhook/runbook binding, accepted invocation, and observed new identity action. |
| `az-privilege-escalation/az-automation-accounts-privesc.md#microsoftautomationautomationaccountsrunbooksdraftwrite-microsoftautomationautomationaccountsrunbooksdraftcontentwrite-microsoftautomationautomationaccountsrunbooksdrafttestjobwrite` | `Microsoft.Automation/automationAccounts/runbooks/draft/write`, `Microsoft.Automation/automationAccounts/runbooks/draft/content/write`, `Microsoft.Automation/automationAccounts/runbooks/draft/testJob/write` | Microsoft.Automation/automationAccounts/runbooks/draft/write;Microsoft.Automation/automationAccounts/runbooks/draft/content/write;Microsoft.Automation/automationAccounts/runbooks/draft/testJob/write | EXCLUDED | Covered by azure-automation-runbook-author-and-run (testJob alternative). |
| `az-privilege-escalation/az-automation-accounts-privesc.md#microsoftautomationautomationaccountssourcecontrolswrite-microsoftautomationautomationaccountssourcecontrolsread` | `Microsoft.Automation/automationAccounts/sourceControls/write`, (`Microsoft.Automation/automationAccounts/sourceControls/read`) | Microsoft.Automation/automationAccounts/sourceControls/write;Microsoft.Automation/automationAccounts/jobs/write;Microsoft.Automation/automationAccounts/jobSchedules/write | EXCLUDED | NEEDS SCHEMA: Source-control import does not prove a bound repository, accepted malicious runbook, later trigger, or execution under the exact account identity. |
| `az-privilege-escalation/az-automation-accounts-privesc.md#microsoftautomationautomationaccountsvariableswrite` | `Microsoft.Automation/automationAccounts/variables/write` | Microsoft.Automation/automationAccounts/variables/write | EXCLUDED | NEEDS SCHEMA: Variable write does not prove an exact runbook consumes the value, executes attacker-controlled code, or exposes the account identity. |
| `az-privilege-escalation/az-automation-accounts-privesc.md#compromising-state-configuration` | Compromising State Configuration |  | EXCLUDED | The referenced flow pushes the configuration with the VM DSC extension (Microsoft.Compute/virtualMachines/extensions/write), already modelled in virtual_machines.yaml; Automation DSC is retiring and exact node-assignment permissions are not documented on the page. |
| `az-privilege-escalation/az-automation-accounts-privesc.md#microsoftautomationautomationaccountspython3packageswrite-microsoftautomationautomationaccountsrunbookswrite-microsoftautomationautomationaccountsrunbooksdraftcontentwrite-microsoftautomationautomationaccountsrunbookspublishaction-microsoftautomationautomationaccountsjobswrite` | `Microsoft.Automation/automationAccounts/python3Packages/write`, `Microsoft.Automation/automationAccounts/runbooks/write`, `Microsoft.Automation/automationAccounts/runbooks/draft/content/write`, `Microsoft.Automation/automationAccounts/runbooks/publish/action`, `Microsoft.Automation/automationAccounts/jobs/write` | Microsoft.Automation/automationAccounts/python3Packages/write;Microsoft.Automation/automationAccounts/runbooks/write;Microsoft.Automation/automationAccounts/runbooks/draft/content/write;Microsoft.Automation/automationAccounts/runbooks/publish/action;Microsoft.Automation/automationAccounts/jobs/write | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-automation-accounts-privesc.md#microsoftautomationautomationaccountsjobswrite-microsoftautomationautomationaccountsrunbooksdraftwrite-microsoftautomationautomationaccountsrunbooksdraftcontentwrite-microsoftautomationautomationaccountsjobsoutputread-microsoftautomationautomationaccountsrunbookspublishaction-microsoftresourcessubscriptionsresourcegroupsread-microsoftautomationautomationaccountsrunbookswrite`, `az-privilege-escalation/az-automation-accounts-privesc.md#poison-a-classic-powershell-dependency-with-moduleswrite` |
| `az-privilege-escalation/az-automation-accounts-privesc.md#automation---malicious-python-packages` | Automation - Malicious Python Packages |  | EXCLUDED | Classic package poisoning NEEDS SCHEMA for exact import and run under named identity; runtime-environment package permission is not grantable as described. |
| `az-privilege-escalation/az-automation-accounts-privesc.md#microsoftautomationautomationaccountsmoduleswrite-microsoftautomationautomationaccountsrunbookswrite-microsoftautomationautomationaccountsrunbooksdraftcontentwrite-microsoftautomationautomationaccountsrunbookspublishaction-microsoftautomationautomationaccountsjobswrite` | `Microsoft.Automation/automationAccounts/modules/write`, `Microsoft.Automation/automationAccounts/runbooks/write`, `Microsoft.Automation/automationAccounts/runbooks/draft/content/write`, `Microsoft.Automation/automationAccounts/runbooks/publish/action`, `Microsoft.Automation/automationAccounts/jobs/write` | Microsoft.Automation/automationAccounts/modules/write;Microsoft.Automation/automationAccounts/runbooks/write;Microsoft.Automation/automationAccounts/runbooks/draft/content/write;Microsoft.Automation/automationAccounts/runbooks/publish/action;Microsoft.Automation/automationAccounts/jobs/write | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-automation-accounts-privesc.md#microsoftautomationautomationaccountsjobswrite-microsoftautomationautomationaccountsrunbooksdraftwrite-microsoftautomationautomationaccountsrunbooksdraftcontentwrite-microsoftautomationautomationaccountsjobsoutputread-microsoftautomationautomationaccountsrunbookspublishaction-microsoftresourcessubscriptionsresourcegroupsread-microsoftautomationautomationaccountsrunbookswrite`, `az-privilege-escalation/az-automation-accounts-privesc.md#poison-a-classic-powershell-dependency-with-moduleswrite` |
| `az-privilege-escalation/az-automation-accounts-privesc.md#automation---malicious-modules` | Automation - Malicious Modules |  | EXCLUDED | NEEDS SCHEMA for exact module import, runbook execution, and named identity outcome. |
| `az-privilege-escalation/az-automation-accounts-privesc.md#abuse-jobscheduleswrite-to-run-an-existing-privileged-runbook` | Abuse `jobSchedules/write` to run an existing privileged runbook | Microsoft.Automation/automationAccounts/jobs/write;Microsoft.Automation/automationAccounts/jobSchedules/write;Microsoft.Automation/automationAccounts/webhooks/write;Microsoft.Automation/automationAccounts/webhooks/action;Microsoft.Automation/automationAccounts/runbooks/read | EXCLUDED | NEEDS SCHEMA: Existing runbook behavior and exact accepted parameters/job execution are uncollected; a trigger grant alone cannot reach the attached managed identity. |
| `az-privilege-escalation/az-automation-accounts-privesc.md#poison-a-classic-powershell-dependency-with-moduleswrite` | Poison a classic PowerShell dependency with `modules/write` | Microsoft.Automation/automationAccounts/modules/write;Microsoft.Automation/automationAccounts/python3Packages/write | EXCLUDED | NEEDS SCHEMA: Module/package write does not prove an exact runbook imports that version and executes it under the named identity. |
| `az-privilege-escalation/az-automation-accounts-privesc.md#references` | References |  | STRUCTURAL | references |

## az-privilege-escalation/az-batch-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-batch-privesc.md#az---batch-privesc` | Az - Batch Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-batch-privesc.md#azure-batch` | Azure Batch |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-batch-privesc.md#microsoftbatchbatchaccountslistkeysaction` | `Microsoft.Batch/batchAccounts/listkeys/action` | Microsoft.Batch/batchAccounts/listKeys/action,Microsoft.Batch/batchAccounts/listkeys/action | MAPPED | `azure-batch-shared-key-task-submission` |
| `az-privilege-escalation/az-batch-privesc.md#microsoftbatchbatchaccountsregeneratekeysaction` | `Microsoft.Batch/batchAccounts/regeneratekeys/action` | Microsoft.Batch/batchAccounts/regenerateKeys/action,Microsoft.Batch/batchAccounts/regeneratekeys/action | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-batch-privesc.md#microsoftbatchbatchaccountslistkeysaction` |
| `az-privilege-escalation/az-batch-privesc.md#read-plaintext-job-and-schedule-configuration` | Read plaintext job and schedule configuration | Microsoft.Batch/batchAccounts/jobSchedules/read,Microsoft.Batch/batchAccounts/jobs/read | EXCLUDED | Moved to post-exploitation; Data read of configuration of unknown content. |
| `az-privilege-escalation/az-batch-privesc.md#azure-batch-job-and-task-data-actions` | Azure Batch job and task data actions | Microsoft.Batch/batchAccounts/jobSchedules/*,Microsoft.Batch/batchAccounts/jobs/* | MAPPED | `azure-batch-job-task-submission` |
| `az-privilege-escalation/az-batch-privesc.md#microsoftbatchbatchaccountspoolswrite--node-rce-via-pool-starttask--managed-identity-attach-control-plane-no-keys` | `Microsoft.Batch/batchAccounts/pools/write` — node RCE via pool `startTask` + managed-identity attach (control-plane, no keys) | Microsoft.Batch/*,Microsoft.Batch/batchAccounts/pools/write | MAPPED | `azure-batch-pool-write-starttask` `azure-batch-pool-write-assign-user-assigned-identity` |
| `az-privilege-escalation/az-batch-privesc.md#microsoftbatchbatchaccountsapplicationsversionswrite--activateaction--application-package-supply-chain-poisoning` | `Microsoft.Batch/batchAccounts/applications/versions/write` (+ `activate/action`) — application-package supply-chain poisoning | Microsoft.Batch/batchAccounts/applications/versions/write,Microsoft.Batch/batchAccounts/applications/write | EXCLUDED | NEEDS SCHEMA: Package activation does not prove a precise pool/task references and executes the modified version or reaches its UAMI. |
| `az-privilege-escalation/az-batch-privesc.md#microsoftbatchbatchaccountswrite--re-enable-sharedkey-auth-re-point-auto-storage-attach-account-identity` | `Microsoft.Batch/batchAccounts/write` — re-enable SharedKey auth, re-point auto-storage, attach account identity | Microsoft.Batch/*,Microsoft.Batch/batchAccounts/write | EXCLUDED | Re-enabling SharedKey / auto-storage repoint is an auth downgrade; the account identity is used by the service (CMK, auto-storage), not exposed to node code. Pool identity paths are modelled separately. |
| `az-privilege-escalation/az-batch-privesc.md#references` | References |  | STRUCTURAL | references/enumeration |

## az-privilege-escalation/az-bot-service-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-bot-service-privesc.md#az---bot-service-privesc` | Az - Bot Service Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-bot-service-privesc.md#azure-bot-service` | Azure Bot Service |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-bot-service-privesc.md#microsoftbotservicebotserviceschannelslistchannelwithkeysaction` | `Microsoft.BotService/botServices/channels/listchannelwithkeys/action` | Microsoft.BotService/botServices/channels/listChannelWithKeys/action,Microsoft.BotService/botServices/channels/listchannelwithkeys/action | EXCLUDED | NEEDS SCHEMA: prove the exact Direct Line channel secret authenticates a concrete bot client identity with effective access beyond the caller. |
| `az-privilege-escalation/az-bot-service-privesc.md#microsoftbotservicebotserviceschannelsregeneratekeysaction` | `Microsoft.BotService/botServices/channels/regeneratekeys/action` | Microsoft.BotService/botServices/channels/regeneratekeys/action | EXCLUDED | NEEDS SCHEMA: prove the exact rotated channel secret authenticates a concrete bot client identity with new effective access; rotation alone is not escalation. |
| `az-privilege-escalation/az-bot-service-privesc.md#microsofthealthbothealthbotslistsecretsaction` | `Microsoft.HealthBot/healthBots/listSecrets/action` | Microsoft.HealthBot/healthBots/listSecrets/action | EXCLUDED | NEEDS SCHEMA: prove the returned secret authenticates a concrete Healthcare Agent management identity and grants effective access beyond the caller. |
| `az-privilege-escalation/az-bot-service-privesc.md#microsofthealthbothealthbotsadminsecretsgenerateapikeyaction` | `Microsoft.HealthBot/healthBots/Admin/Secrets/GenerateApiKey/Action` | Microsoft.HealthBot/healthBots/Admin/Secrets/GenerateApiKey/Action | EXCLUDED | NEEDS SCHEMA: prove the generated API key authenticates a concrete Healthcare Agent management identity and grants effective access beyond the caller. |
| `az-privilege-escalation/az-bot-service-privesc.md#references` | References |  | STRUCTURAL | section/how-to heading; no technique |

## az-privilege-escalation/az-communication-services-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-communication-services-privesc.md#az---communication-services-privesc` | Az - Communication Services Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-communication-services-privesc.md#communication-services` | Communication Services |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-communication-services-privesc.md#microsoftcommunicationcommunicationserviceswrite` | `Microsoft.Communication/CommunicationServices/Write` | Microsoft.Communication/CommunicationServices/Write | EXCLUDED | NEEDS SCHEMA: Exact ACS communication identity and newly authorized service action after the write must be verified. |
| `az-privilege-escalation/az-communication-services-privesc.md#microsoftcommunicationcommunicationserviceslistkeysaction` | `Microsoft.Communication/CommunicationServices/ListKeys/action` | Microsoft.Communication/CommunicationServices/ListKeys/action | EXCLUDED | NEEDS SCHEMA: Exact ACS service/key identity, usable key authority, and additional permitted action must be verified. |
| `az-privilege-escalation/az-communication-services-privesc.md#org-domain-phishing-infrastructure-with-emailservicesdomainssenderusernameswrite` | Org-domain phishing infrastructure with `EmailServices/Domains/SenderUsernames/write` |  | STRUCTURAL | pointer to post-exploitation page |
| `az-privilege-escalation/az-communication-services-privesc.md#push-channel-redirect-with-communicationserviceslinknotificationhubaction` | Push-channel redirect with `CommunicationServices/LinkNotificationHub/action` |  | STRUCTURAL | pointer to post-exploitation page |
| `az-privilege-escalation/az-communication-services-privesc.md#inbound-sms2fa-interception-with-communicationserviceseventgridfilterswrite` | Inbound SMS/2FA interception with `CommunicationServices/EventGridFilters/Write` |  | EXCLUDED | NEEDS SCHEMA: Exact intercepted factor, named account subject, and successful newly authorized account action must be verified; message interception alone is terminal. |
| `az-privilege-escalation/az-communication-services-privesc.md#references` | References |  | STRUCTURAL | references |

## az-privilege-escalation/az-confidential-ledger-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-confidential-ledger-privesc.md#az---confidential-ledger-privesc` | Az - Confidential Ledger Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-confidential-ledger-privesc.md#confidential-ledger` | Confidential Ledger |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-confidential-ledger-privesc.md#data-plane-role-self-grant-via-ledgerswrite` | Data-plane role self-grant via `ledgers/write` | Microsoft.ConfidentialLedger/ledgers/write | MAPPED | `azure-confidentialledger-ledgers-write-principal` |
| `az-privilege-escalation/az-confidential-ledger-privesc.md#references` | References |  | STRUCTURAL | section/how-to heading; no technique |

## az-privilege-escalation/az-container-apps-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-container-apps-privesc.md#az---container-apps-privesc` | Az - Container Apps Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-container-apps-privesc.md#container-apps` | Container Apps |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-container-apps-privesc.md#microsoftappmanagedenvironmentsdaprcomponentswrite---redirect-a-future-dapr-operation` | `Microsoft.App/managedEnvironments/daprComponents/write` - Redirect a future Dapr operation | Microsoft.App/managedEnvironments/daprComponents/write | STRUCTURAL | pointer to post-exploitation page |
| `az-privilege-escalation/az-container-apps-privesc.md#references` | References |  | STRUCTURAL | references/enumeration |

## az-privilege-escalation/az-container-instances-apps-jobs-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#az---azure-container-instances-apps--jobs-privesc` | Az - Azure Container Instances, Apps & Jobs Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#container-instances-container-apps-and-jobs` | Container Instances, Container Apps and Jobs |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#azure-container-instances-apps--jobs` | Azure Container Instances, Apps & Jobs |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#aci` | ACI |  | STRUCTURAL | section grouping heading; techniques are its subsections |
| `az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#microsoftcontainerinstancecontainergroupsread-microsoftcontainerinstancecontainergroupscontainersexecaction` | `Microsoft.ContainerInstance/containerGroups/read`, `Microsoft.ContainerInstance/containerGroups/containers/exec/action` | Microsoft.ContainerInstance/containerGroups/containers/exec/action,Microsoft.ContainerInstance/containerGroups/read | MAPPED | `azure-aci-container-exec` |
| `az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#microsoftcontainerinstancecontainergroupswrite-environment-update` | `Microsoft.ContainerInstance/containerGroups/write` (environment update) | Microsoft.ContainerInstance/containerGroups/write | MAPPED | `azure-aci-containergroup-write-existing` |
| `az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#microsoftcontainerinstancecontainergroupswrite-microsoftmanagedidentityuserassignedidentitiesassignaction` | `Microsoft.ContainerInstance/containerGroups/write`, `Microsoft.ManagedIdentity/userAssignedIdentities/assign/action` | Microsoft.ContainerInstance/containerGroups/write,Microsoft.ManagedIdentity/userAssignedIdentities/assign/action | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#microsoftresourcessubscriptionsresourcegroupsread-microsoftcontainerinstancecontainergroupswrite-microsoftmanagedidentityuserassignedidentitiesassignaction` |
| `az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#microsoftresourcessubscriptionsresourcegroupsread-microsoftcontainerinstancecontainergroupswrite-microsoftmanagedidentityuserassignedidentitiesassignaction` | `Microsoft.Resources/subscriptions/resourcegroups/read`, `Microsoft.ContainerInstance/containerGroups/write`, `Microsoft.ManagedIdentity/userAssignedIdentities/assign/action` | Microsoft.ContainerInstance/containerGroups/write,Microsoft.ManagedIdentity/userAssignedIdentities/assign/action,Microsoft.Resources/subscriptions/resourcegroups/read | MAPPED | `azure-aci-assign-user-assigned-identity` |
| `az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#microsoftcontainerinstancecontainergroupsrestartaction-microsoftcontainerinstancecontainergroupsstartaction` | `Microsoft.ContainerInstance/containerGroups/restart/action`, `Microsoft.ContainerInstance/containerGroups/start/action` | Microsoft.ContainerInstance/containerGroups/restart/action,Microsoft.ContainerInstance/containerGroups/start/action | EXCLUDED | Replays unchanged startup; no attacker-controlled code (page: Medium). |
| `az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#aca` | ACA |  | STRUCTURAL | section grouping heading; techniques are its subsections |
| `az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#microsoftappcontainerappsread-microsoftappmanagedenvironmentsread-microsoftappcontainerappsrevisionsreplicasread-microsoftappcontainerappsrevisionsread-microsoftappcontainerappsgetauthtokenaction-microsoftappcontainerappsexecaction-microsoftappcontainerappsdebugaction` | `Microsoft.App/containerApps/read`, `Microsoft.App/managedEnvironments/read`, `Microsoft.App/containerApps/revisions/replicas/read`, `Microsoft.App/containerApps/revisions/read`, `Microsoft.App/containerApps/getAuthToken/action`, `Microsoft.App/containerApps/exec/action`, `Microsoft.App/containerApps/debug/action` | Microsoft.App/containerApps/debug/action,Microsoft.App/containerApps/exec/action,Microsoft.App/containerApps/getAuthToken/action,Microsoft.App/containerApps/read,Microsoft.App/containerApps/revisions/read,Microsoft.App/containerApps/revisions/replicas/read,Microsoft.App/managedEnvironments/read | MAPPED | `azure-containerapp-exec` |
| `az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#microsoftappcontainerappslistsecretsaction` | `Microsoft.App/containerApps/listSecrets/action` | Microsoft.App/containerApps/listSecrets/action | EXCLUDED | Strict principal-boundary audit: The credential_stored_in_scope selector has no exact usable credential and identified target-principal evidence enforcement for this technique; a secret read or arbitrary configuration change alone is not an established principal escalation. |
| `az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#microsoftappcontainerappsrevisionsactivateaction-microsoftappcontainerappsrevisionsrestartaction-microsoftappcontainerappsstartaction` | `Microsoft.App/containerApps/revisions/activate/action`, `Microsoft.App/containerApps/revisions/restart/action`, `Microsoft.App/containerApps/start/action` | Microsoft.App/containerApps/revisions/activate/action,Microsoft.App/containerApps/revisions/restart/action,Microsoft.App/containerApps/start/action | EXCLUDED | Runs existing code only; no attacker-controlled code. |
| `az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#microsoftappmanagedenvironmentsdaprcomponentslistsecretsaction` | `Microsoft.App/managedEnvironments/daprComponents/listSecrets/action` | Microsoft.App/managedEnvironments/daprComponents/listSecrets/action | EXCLUDED | Strict principal-boundary audit: The credential_stored_in_scope selector has no exact usable credential and identified target-principal evidence enforcement for this technique; a secret read or arbitrary configuration change alone is not an established principal escalation. |
| `az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#microsoftappcontainerappswrite` | `Microsoft.App/containerApps/write` | Microsoft.App/containerApps/write | MAPPED | `azure-containerapp-write-existing` |
| `az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#microsoftappcontainerappswrite-microsoftmanagedidentityuserassignedidentitiesassignaction` | `Microsoft.App/containerApps/write`, `Microsoft.ManagedIdentity/userAssignedIdentities/assign/action` | Microsoft.App/containerApps/write,Microsoft.ManagedIdentity/userAssignedIdentities/assign/action | MAPPED | `azure-containerapp-assign-user-assigned-identity` |
| `az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#microsoftappcontainerappswrite-microsoftmanagedidentityuserassignedidentitiesassignaction-microsoftappmanagedenvironmentsjoinaction` | `Microsoft.App/containerApps/write`, `Microsoft.ManagedIdentity/userAssignedIdentities/assign/action`, `Microsoft.App/managedEnvironments/join/action` | Microsoft.App/containerApps/write,Microsoft.App/managedEnvironments/join/action,Microsoft.ManagedIdentity/userAssignedIdentities/assign/action | MAPPED | `azure-containerapp-create-with-user-assigned-identity` |
| `az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#dynamic-sessions` | Dynamic sessions |  | STRUCTURAL | section grouping heading; techniques are its subsections |
| `az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#microsoftappsessionpoolsfetchmcpservercredentialsaction` | `Microsoft.App/sessionPools/fetchMCPServerCredentials/action` | Microsoft.App/sessionPools/fetchMCPServerCredentials/action | EXCLUDED | NEEDS SCHEMA: MCP credential fetch does not prove identity exposure is enabled for the exact session pool or that the caller acquired a usable identity token. |
| `az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#microsoftappsessionpoolsexecutionsaction` | `Microsoft.App/sessionPools/executions/action` | Microsoft.App/sessionPools/executions/action | EXCLUDED | NEEDS SCHEMA: Session execution grant does not prove the exact session exposes the attached managed identity or a usable token/new action was obtained. |
| `az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#microsoftappsessionpoolsfilescontentread` | `Microsoft.App/sessionPools/files/content/read` | Microsoft.App/sessionPools/files/content/read | EXCLUDED | Data read. |
| `az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#aca-sandboxes` | ACA Sandboxes |  | STRUCTURAL | section grouping heading; techniques are its subsections |
| `az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#microsoftappsandboxgroupssandboxesexecutecommandaction-and-microsoftappsandboxgroupssandboxesexecuteshellcommandaction` | `Microsoft.App/sandboxGroups/sandboxes/executeCommand/action` and `Microsoft.App/sandboxGroups/sandboxes/executeShellCommand/action` | Microsoft.App/sandboxGroups/sandboxes/executeCommand/action,Microsoft.App/sandboxGroups/sandboxes/executeShellCommand/action | EXCLUDED | Code execution in isolated sandbox; page does not state a managed identity is reachable. |
| `az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#microsoftappsandboxgroupssandboxesfilesread` | `Microsoft.App/sandboxGroups/sandboxes/files/read` | Microsoft.App/sandboxGroups/sandboxes/files/read | EXCLUDED | Data read. |
| `az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#microsoftappsandboxgroupssecretspeekaction` | `Microsoft.App/sandboxGroups/secrets/peek/action` | Microsoft.App/sandboxGroups/secrets/peek/action | EXCLUDED | Strict principal-boundary audit: The credential_stored_in_scope selector has no exact usable credential and identified target-principal evidence enforcement for this technique; a secret read or arbitrary configuration change alone is not an established principal escalation. |
| `az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#cloud-builds` | Cloud builds |  | STRUCTURAL | section grouping heading; techniques are its subsections |
| `az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#microsoftappbuildslistauthtokenaction` | `Microsoft.App/builds/listAuthToken/action` | Microsoft.App/builds/listAuthToken/action | EXCLUDED | Page states impact not demonstrated; conditional and not modelable. |
| `az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#jobs` | Jobs |  | STRUCTURAL | section grouping heading; techniques are its subsections |
| `az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#microsoftappjobsstartaction-microsoftappjobsread` | `Microsoft.App/jobs/start/action`, (`Microsoft.App/jobs/read`) | Microsoft.App/jobs/read,Microsoft.App/jobs/start/action | MAPPED | `azure-containerapp-job-start-template-override` |
| `az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#microsoftappjobsread-microsoftappjobslistsecretsaction` | `Microsoft.App/jobs/read`, `Microsoft.App/jobs/listSecrets/action` | Microsoft.App/jobs/listSecrets/action,Microsoft.App/jobs/read | EXCLUDED | Strict principal-boundary audit: The credential_stored_in_scope selector has no exact usable credential and identified target-principal evidence enforcement for this technique; a secret read or arbitrary configuration change alone is not an established principal escalation. |
| `az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#microsoftmanagedidentityuserassignedidentitiesassignaction-microsoftappjobswrite` | `Microsoft.ManagedIdentity/userAssignedIdentities/assign/action`, `Microsoft.App/jobs/write` | Microsoft.App/jobs/write,Microsoft.ManagedIdentity/userAssignedIdentities/assign/action | MAPPED | `azure-containerapp-job-assign-user-assigned-identity` |
| `az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#microsoftappmanagedenvironmentsread-microsoftappjobswrite-microsoftappmanagedenvironmentsjoinaction-microsoftmanagedidentityuserassignedidentitiesassignaction` | `Microsoft.App/managedEnvironments/read`, `Microsoft.App/jobs/write`, `Microsoft.App/managedEnvironments/join/action`, `Microsoft.ManagedIdentity/userAssignedIdentities/assign/action` | Microsoft.App/jobs/write,Microsoft.App/managedEnvironments/join/action,Microsoft.App/managedEnvironments/read,Microsoft.ManagedIdentity/userAssignedIdentities/assign/action | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#microsoftmanagedidentityuserassignedidentitiesassignaction-microsoftappjobswrite` |
| `az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#references` | References |  | STRUCTURAL | references/enumeration |

## az-privilege-escalation/az-container-registry-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-container-registry-privesc.md#az---azure-container-registry-privesc` | Az - Azure Container Registry Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-container-registry-privesc.md#container-registry` | Container Registry |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-container-registry-privesc.md#azure-container-registry` | Azure Container Registry |  | STRUCTURAL | section grouping heading; techniques are its subsections |
| `az-privilege-escalation/az-container-registry-privesc.md#microsoftcontainerregistryregistrieslistcredentialsaction` | `Microsoft.ContainerRegistry/registries/listCredentials/action` | Microsoft.ContainerRegistry/registries/listCredentials/action | EXCLUDED | Strict principal-boundary audit: The source permission or capability needed to perform the stated write/action is absent from requires; reviewed target evidence alone cannot establish the X permission to Y action escalation path. |
| `az-privilege-escalation/az-container-registry-privesc.md#microsoftcontainerregistryregistriesregeneratecredentialaction` | `Microsoft.ContainerRegistry/registries/regenerateCredential/action` | Microsoft.ContainerRegistry/registries/regenerateCredential/action | EXCLUDED | Strict principal-boundary audit: The source permission or capability needed to perform the stated write/action is absent from requires; reviewed target evidence alone cannot establish the X permission to Y action escalation path. |
| `az-privilege-escalation/az-container-registry-privesc.md#microsoftcontainerregistryregistriesgeneratecredentialsaction` | `Microsoft.ContainerRegistry/registries/generateCredentials/action` | Microsoft.ContainerRegistry/registries/generateCredentials/action | EXCLUDED | Strict principal-boundary audit: The source permission or capability needed to perform the stated write/action is absent from requires; reviewed target evidence alone cannot establish the X permission to Y action escalation path. |
| `az-privilege-escalation/az-container-registry-privesc.md#microsoftcontainerregistryregistriesrunslistlogsasurlaction` | `Microsoft.ContainerRegistry/registries/runs/listLogSasUrl/action` | Microsoft.ContainerRegistry/registries/runs/listLogSasUrl/action | EXCLUDED | Data read. |
| `az-privilege-escalation/az-container-registry-privesc.md#microsoftcontainerregistryregistriestaskslistdetailsaction-microsoftcontainerregistryregistriestaskrunslistdetailsaction` | `Microsoft.ContainerRegistry/registries/tasks/listDetails/action`, `Microsoft.ContainerRegistry/registries/taskruns/listDetails/action` | Microsoft.ContainerRegistry/registries/taskruns/listDetails/action,Microsoft.ContainerRegistry/registries/tasks/listDetails/action | EXCLUDED | Secret read of unknown content. |
| `az-privilege-escalation/az-container-registry-privesc.md#microsoftcontainerregistryregistriestaskrunswrite` | `Microsoft.ContainerRegistry/registries/taskruns/write` | Microsoft.ContainerRegistry/registries/taskruns/write | EXCLUDED | Strict principal-boundary audit: The source permission or capability needed to perform the stated write/action is absent from requires; reviewed target evidence alone cannot establish the X permission to Y action escalation path. |
| `az-privilege-escalation/az-container-registry-privesc.md#microsoftcontainerregistryregistriesschedulerunaction` | `Microsoft.ContainerRegistry/registries/scheduleRun/action` | Microsoft.ContainerRegistry/registries/scheduleRun/action | EXCLUDED | Strict principal-boundary audit: The source permission or capability needed to perform the stated write/action is absent from requires; reviewed target evidence alone cannot establish the X permission to Y action escalation path. |
| `az-privilege-escalation/az-container-registry-privesc.md#microsoftcontainerregistryregistriestaskswrite` | `Microsoft.ContainerRegistry/registries/tasks/write` | Microsoft.ContainerRegistry/registries/tasks/write,Microsoft.ManagedIdentity/userAssignedIdentities/assign/action | MAPPED | `azure-acr-task-write-existing-identity` `azure-acr-task-assign-user-assigned-identity` |
| `az-privilege-escalation/az-container-registry-privesc.md#microsoftcontainerregistryregistriesimportimageaction` | `Microsoft.ContainerRegistry/registries/importImage/action` | Microsoft.ContainerRegistry/registries/importImage/action | EXCLUDED | Strict principal-boundary audit: The source permission or capability needed to perform the stated write/action is absent from requires; reviewed target evidence alone cannot establish the X permission to Y action escalation path. |
| `az-privilege-escalation/az-container-registry-privesc.md#microsoftcontainerregistryregistrieswebhooksgetcallbackconfigaction` | Microsoft.ContainerRegistry/registries/webhooks/getCallbackConfig/action | Microsoft.ContainerRegistry/registries/webhooks/getCallbackConfig/action | EXCLUDED | Callback secret read. |
| `az-privilege-escalation/az-container-registry-privesc.md#microsoftcontainerregistryregistrieswebhookswrite--outbound-event-exfiltration--ci-cd-recon` | `Microsoft.ContainerRegistry/registries/webhooks/write` — outbound event exfiltration / CI-CD recon | Microsoft.ContainerRegistry/registries/webhooks/write | EXCLUDED | Push/pull event metadata exfiltration; no identity. |
| `az-privilege-escalation/az-container-registry-privesc.md#microsoftcontainerregistryregistriescacheruleswrite-credentialsetswrite--cache-rule-redirect--supply-chain` | `Microsoft.ContainerRegistry/registries/cacheRules/write`, `credentialSets/write` — cache-rule redirect / supply chain | Microsoft.ContainerRegistry/registries/cacheRules/write,Microsoft.ContainerRegistry/registries/credentialSets/write | EXCLUDED | Strict principal-boundary audit: The source permission or capability needed to perform the stated write/action is absent from requires; reviewed target evidence alone cannot establish the X permission to Y action escalation path. |
| `az-privilege-escalation/az-container-registry-privesc.md#microsoftcontainerregistryregistrieswrite--network-exposure--lockout` | `Microsoft.ContainerRegistry/registries/write` — network exposure / lockout | Microsoft.ContainerRegistry/registries/write | EXCLUDED | Posture change or DoS; no identity. |
| `az-privilege-escalation/az-container-registry-privesc.md#customer-managed-key-cmk-revocation--registry-ransom--dos` | Customer-managed key (CMK) revocation — registry ransom / DoS | Microsoft.ContainerRegistry/registries/write,Microsoft.KeyVault/vaults/keys/write | EXCLUDED | Denial of service; no identity. |
| `az-privilege-escalation/az-container-registry-privesc.md#mutable-image-tag-poisoning-with-repository-content-permissions` | Mutable image tag poisoning with repository content permissions | Microsoft.ContainerRegistry/registries/repositories/content/read | EXCLUDED | NEEDS SCHEMA: Mutable tag overwrite does not establish an exact registry-image-to-container-app binding, new revision execution, or identity token access. |
| `az-privilege-escalation/az-container-registry-privesc.md#references` | References |  | STRUCTURAL | references/enumeration |
| `az-privilege-escalation/az-container-registry-privesc.md#references-1` | References |  | STRUCTURAL | references/enumeration |

## az-privilege-escalation/az-cosmosDB-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-cosmosDB-privesc.md#az---cosmosdb-privesc` | Az - CosmosDB Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-cosmosDB-privesc.md#cosmosdb` | CosmosDB |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-cosmosDB-privesc.md#cosmosdb-privesc` | CosmosDB Privesc |  | STRUCTURAL | section/how-to heading; no technique |
| `az-privilege-escalation/az-cosmosDB-privesc.md#microsoftdocumentdbdatabaseaccountssqlroledefinitionswrite-microsoftdocumentdbdatabaseaccountssqlroledefinitionsread--microsoftdocumentdbdatabaseaccountssqlroleassignmentswrite-microsoftdocumentdbdatabaseaccountssqlroleassignmentsread` | (`Microsoft.DocumentDB/databaseAccounts/sqlRoleDefinitions/write`, `Microsoft.DocumentDB/databaseAccounts/sqlRoleDefinitions/read`) & (`Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments/write`, `Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments/read`) | Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments/read,Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments/write,Microsoft.DocumentDB/databaseAccounts/sqlRoleDefinitions/read,Microsoft.DocumentDB/databaseAccounts/sqlRoleDefinitions/write | MAPPED | `azure-cosmos-sql-role-assignment-write` |
| `az-privilege-escalation/az-cosmosDB-privesc.md#microsoftdocumentdbdatabaseaccountsmongodbroledefinitionswrite--microsoftdocumentdbdatabaseaccountsmongodbroledefinitionsread-microsoftdocumentdbdatabaseaccountsmongodbuserdefinitionswrite--microsoftdocumentdbdatabaseaccountsmongodbuserdefinitionsread` | (`Microsoft.DocumentDB/databaseAccounts/mongodbRoleDefinitions/write` && `Microsoft.DocumentDB/databaseAccounts/mongodbRoleDefinitions/read`)&& (`Microsoft.DocumentDB/databaseAccounts/mongodbUserDefinitions/write` && `Microsoft.DocumentDB/databaseAccounts/mongodbUserDefinitions/read`) | Microsoft.DocumentDB/databaseAccounts/mongodbRoleDefinitions/read,Microsoft.DocumentDB/databaseAccounts/mongodbRoleDefinitions/write,Microsoft.DocumentDB/databaseAccounts/mongodbUserDefinitions/read,Microsoft.DocumentDB/databaseAccounts/mongodbUserDefinitions/write | MAPPED | `azure-cosmos-mongodb-user-definition-write` |
| `az-privilege-escalation/az-cosmosDB-privesc.md#same-native-rbac-self-grant-on-the-other-cosmos-apis-cassandra--gremlin--table--mongo-vcore` | Same native-RBAC self-grant on the other Cosmos APIs (Cassandra / Gremlin / Table / Mongo vCore) | Microsoft.DocumentDB/databaseAccounts/cassandraRoleDefinitions/write | MAPPED | `azure-cosmos-other-api-role-assignment-write` |
| `az-privilege-escalation/az-cosmosDB-privesc.md#microsoftdocumentdbdatabaseaccountslistkeysaction` | `Microsoft.DocumentDB/databaseAccounts/listKeys/action` | Microsoft.DocumentDB/databaseAccounts/listKeys/action | EXCLUDED | Data-plane key; data access. |
| `az-privilege-escalation/az-cosmosDB-privesc.md#microsoftdocumentdbdatabaseaccountslistconnectionstringsaction` | `Microsoft.DocumentDB/databaseAccounts/listConnectionStrings/action` | Microsoft.DocumentDB/databaseAccounts/listConnectionStrings/action | EXCLUDED | Data-plane key; data access. |
| `az-privilege-escalation/az-cosmosDB-privesc.md#microsoftdocumentdbdatabaseaccountsreadonlykeysaction` | `Microsoft.DocumentDB/databaseAccounts/readonlykeys/action` | Microsoft.DocumentDB/databaseAccounts/readonlykeys/action | EXCLUDED | Data read. |
| `az-privilege-escalation/az-cosmosDB-privesc.md#microsoftinferenceserviceinferenceaccountslistkeysaction` | `Microsoft.InferenceService/inferenceAccounts/listKeys/action` | Microsoft.InferenceService/inferenceAccounts/listKeys/action | EXCLUDED | Billed inference access only. |
| `az-privilege-escalation/az-cosmosDB-privesc.md#microsoftinferenceserviceinferenceaccountsregeneratekeysaction` | `Microsoft.InferenceService/inferenceAccounts/regenerateKeys/action` | Microsoft.InferenceService/inferenceAccounts/regenerateKeys/action | EXCLUDED | Rotate-and-capture of the semantic reranker key gives billed inference access only; no Azure identity. |
| `az-privilege-escalation/az-cosmosDB-privesc.md#microsoftinferenceserviceinferenceaccountsinvokesemanticrerankeraction` | `Microsoft.InferenceService/inferenceAccounts/invoke/semanticReranker/action` | Microsoft.InferenceService/inferenceAccounts/invoke/semanticReranker/action | EXCLUDED | Inference usage; no identity. |
| `az-privilege-escalation/az-cosmosDB-privesc.md#other-current-inference-service-boundaries` | Other current Inference Service boundaries |  | EXCLUDED | Boundary notes; no technique. |
| `az-privilege-escalation/az-cosmosDB-privesc.md#microsoftdocumentdbmongoclustersread--microsoftdocumentdbmongoclusterswrite` | `Microsoft.DocumentDB/mongoClusters/read` , `Microsoft.DocumentDB/mongoClusters/write` | Microsoft.DocumentDB/mongoClusters/read,Microsoft.DocumentDB/mongoClusters/write | MAPPED | `azure-cosmos-mongocluster-admin-password` |
| `az-privilege-escalation/az-cosmosDB-privesc.md#microsoftdocumentdbmongoclustersread--microsoftdocumentdbmongoclustersfirewallruleswrite` | `Microsoft.DocumentDB/mongoClusters/read` , `Microsoft.DocumentDB/mongoClusters/firewallRules/write` | Microsoft.DocumentDB/mongoClusters/firewallRules/write,Microsoft.DocumentDB/mongoClusters/read | EXCLUDED | Network exposure only. |
| `az-privilege-escalation/az-cosmosDB-privesc.md#microsoftdocumentdbmongoclusterslistconnectionstringsaction--mongoclustersusersread--userswrite` | `Microsoft.DocumentDB/mongoClusters/listConnectionStrings/action` (+ `mongoClusters/users/read` / `users/write`) | Microsoft.DocumentDB/mongoClusters/listConnectionStrings/action,Microsoft.DocumentDB/mongoClusters/users/read,Microsoft.DocumentDB/mongoClusters/users/write | MAPPED | `azure-cosmos-mongocluster-user-write` |
| `az-privilege-escalation/az-cosmosDB-privesc.md#references` | References |  | STRUCTURAL | section/how-to heading; no technique |

## az-privilege-escalation/az-data-explorer-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-data-explorer-privesc.md#az---data-explorer-kusto-privesc` | Az - Data Explorer (Kusto) Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-data-explorer-privesc.md#azure-data-explorer` | Azure Data Explorer |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-data-explorer-privesc.md#microsoftkustoclustersdatabasesprincipalassignmentswrite` | `Microsoft.Kusto/clusters/databases/principalAssignments/write` | Microsoft.Kusto/clusters/databases/principalAssignments/write | MAPPED | `azure-kusto-database-principal-assignment-write` |
| `az-privilege-escalation/az-data-explorer-privesc.md#cluster-wide-variant-microsoftkustoclustersprincipalassignmentswrite` | Cluster-wide variant: `Microsoft.Kusto/clusters/principalAssignments/write` | Microsoft.Kusto/clusters/principalAssignments/write | MAPPED | `azure-kusto-cluster-principal-assignment-write` |
| `az-privilege-escalation/az-data-explorer-privesc.md#microsoftkustoclustersdatabasesaddprincipalsaction--direct-principal-add-stealthier-than-principalassignments` | `Microsoft.Kusto/Clusters/Databases/AddPrincipals/action` — direct principal add (stealthier than principalAssignments) | Microsoft.Kusto/Clusters/Databases/AddPrincipals/action | MAPPED | `azure-kusto-database-add-principals` |

## az-privilege-escalation/az-data-factory-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-data-factory-privesc.md#az---data-factory-privesc` | Az - Data Factory Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-data-factory-privesc.md#data-factory` | Data Factory |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-data-factory-privesc.md#microsoftdatafactoryfactoriesintegrationruntimeslistauthkeysaction` | `Microsoft.DataFactory/factories/integrationruntimes/listauthkeys/action` | Microsoft.DataFactory/datafactories/gateways/listauthkeys/action,Microsoft.DataFactory/factories/integrationruntimes/listauthkeys/action | EXCLUDED | Strict principal-boundary audit: The credential_stored_in_scope selector has no exact usable credential and identified target-principal evidence enforcement for this technique; a secret read or arbitrary configuration change alone is not an established principal escalation. |
| `az-privilege-escalation/az-data-factory-privesc.md#pipelineswrite--pipelinescreaterunaction--steal-the-factory-managed-identity-token` | `pipelines/write` + `pipelines/createRun/action` — steal the factory managed identity token | Microsoft.DataFactory/factories/pipelines/createRun/action,Microsoft.DataFactory/factories/pipelines/write | EXCLUDED | NEEDS SCHEMA: Pipeline write and run do not prove which exact factory credential object or attached UAMI the run used and what usable token/new action the source obtained. |
| `az-privilege-escalation/az-data-factory-privesc.md#microsoftdatafactoryfactoriespipelinescreaterunaction` | `Microsoft.DataFactory/factories/pipelines/createRun/action` | Microsoft.DataFactory/factories/pipelines/createRun/action,Microsoft.DataFactory/factories/pipelines/read | EXCLUDED | No attacker-controlled code; existing pipeline behaviour only. |
| `az-privilege-escalation/az-data-factory-privesc.md#redirect-factory-output-through-microsoftdatafactoryfactoriesglobalparameterswrite` | Redirect factory output through `Microsoft.DataFactory/factories/globalParameters/write` | Microsoft.DataFactory/factories/globalParameters/write | EXCLUDED | NEEDS SCHEMA: Parameter redirection needs an exact identity-authenticated pipeline, accepted attacker URL parameter, subsequent trigger, and observed credential/new-action outcome. |
| `az-privilege-escalation/az-data-factory-privesc.md#pivot-through-blob-backed-pipeline-configuration-without-data-factory-permissions` | Pivot through Blob-backed pipeline configuration without Data Factory permissions | Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write | EXCLUDED | Pipeline-specific trust in blob content; not modelable from RBAC. |
| `az-privilege-escalation/az-data-factory-privesc.md#read-plaintext-parameters-from-pipeline-run-history` | Read plaintext parameters from pipeline-run history | Microsoft.DataFactory/factories/pipelineruns/read,Microsoft.DataFactory/factories/querypipelineruns/action,Microsoft.DataFactory/factories/querypipelineruns/read | EXCLUDED | Moved to post-exploitation; Data read. |
| `az-privilege-escalation/az-data-factory-privesc.md#rce-as-msi-via-a-debug-sandbox-run-no-pipelineswrite` | RCE-as-MSI via a "Debug" sandbox run (no `pipelines/write`) | Microsoft.DataFactory/factories/pipelines/sandbox/create/action,Microsoft.DataFactory/factories/pipelines/sandbox/run/action | EXCLUDED | NEEDS SCHEMA: Debug execution does not prove exact linked-service credential/UAMI binding, supported activity sandbox, and a usable token/new action. |
| `az-privilege-escalation/az-data-factory-privesc.md#mint-a-factory-data-plane-access-token-with-factoriesgetdataplaneaccessaction` | Mint a factory data-plane access token with `factories/getDataPlaneAccess/action` | Microsoft.DataFactory/factories/getDataPlaneAccess/action | MAPPED | `azure-datafactory-dataplane-access-token` only with typed exact token, runnable pipeline, identity credential binding, successful execution, and obtained MI token evidence. |
| `az-privilege-escalation/az-data-factory-privesc.md#steal-the-factorys-github-oauth-token-with-factoriesgetgithubaccesstokenaction` | Steal the factory's GitHub OAuth token with `factories/getGitHubAccessToken/action` | Microsoft.DataFactory/factories/getGitHubAccessToken/action | MAPPED | `azure-datafactory-github-oauth-external-principal` requires exact GitHub subject and repository, usable token, prior denial, and newly allowed action; historical broad entry remains excluded. |
| `az-privilege-escalation/az-data-factory-privesc.md#self-hosted-ir-key-rotation-connection-recon-and-cross-factory-sharing` | Self-hosted IR key rotation, connection recon and cross-factory sharing | Microsoft.DataFactory/factories/integrationruntimes/regenerateauthkey/action | EXCLUDED | Rogue IR node registration relays linked-service credentials/data on-prem; no Azure identity, consistent with integrationRuntimes listAuthKeys (rev 171e422; linked-service sink section moved to post-exploitation). |
| `az-privilege-escalation/az-data-factory-privesc.md#os-level-rce-on-external-compute-batch--databricks--hdinsight-via-a-pipeline-activity` | OS-level RCE on external compute (Batch / Databricks / HDInsight) via a pipeline activity | Microsoft.Batch/*,Microsoft.DataFactory/factories/pipelines/createRun/action,Microsoft.DataFactory/factories/pipelines/write | EXCLUDED | The reached Batch pool / Databricks / HDInsight cluster is fixed by linked-service configuration and not RBAC-determinable; the factory-identity path is azure-datafactory-pipeline-write-and-run. |

## az-privilege-escalation/az-database-migration-service-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-database-migration-service-privesc.md#az---database-migration-service-dms-privesc` | Az - Database Migration Service (DMS) Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-database-migration-service-privesc.md#database-migration-service` | Database Migration Service |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-database-migration-service-privesc.md#microsoftdatamigrationsqlmigrationserviceslistauthkeysaction--rogue-ir-worker-on-prem-credential-relay` | `Microsoft.DataMigration/sqlMigrationServices/listAuthKeys/action` — rogue IR worker (on-prem credential relay) | Microsoft.DataMigration/sqlMigrationServices/listAuthKeys/action | EXCLUDED | NEEDS SCHEMA: a rogue DMS integration runtime may obtain an on-prem SQL credential, but the exact SQL login, usable secret, observed target authority, and prior-absence proof are not verified. |
| `az-privilege-escalation/az-database-migration-service-privesc.md#microsoftsqlserverswrite-bundled-in-the-migration-roles--unexpected-sql-control-plane-reach` | `Microsoft.Sql/servers/write` bundled in the migration roles — unexpected SQL control-plane reach | Microsoft.Sql/servers/write | EXCLUDED | Covered by azure-sql-server-admin-password-reset. |
| `az-privilege-escalation/az-database-migration-service-privesc.md#references` | References |  | STRUCTURAL | section/how-to heading; no technique |

## az-privilege-escalation/az-databricks-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-databricks-privesc.md#az---databricks-privesc` | Az - Databricks Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-databricks-privesc.md#azure-databricks` | Azure Databricks |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-databricks-privesc.md#become-a-workspace-admin-through-azure-rbac` | Become a workspace admin through Azure RBAC | Microsoft.Databricks/workspaces/assignWorkspaceAdmin/action,Microsoft.Databricks/workspaces/read | MAPPED | `azure-databricks-assign-workspace-admin` |
| `az-privilege-escalation/az-databricks-privesc.md#direct-api-technique` | Direct API technique | Microsoft.Databricks/workspaces/assignWorkspaceAdmin/action,Microsoft.Databricks/workspaces/read | SUBSECTION | of #become-a-workspace-admin-through-azure-rbac: MAPPED azure-databricks-assign-workspace-admin |
| `az-privilege-escalation/az-databricks-privesc.md#cluster-init-scripts--notebook-code--rce--steal-the-cluster--workspace-managed-identity` | Cluster init scripts / notebook code = RCE → steal the cluster / workspace managed identity |  | EXCLUDED | Requires Databricks workspace entitlements, not Azure RBAC; the ARM entry point is azure-databricks-assign-workspace-admin. |
| `az-privilege-escalation/az-databricks-privesc.md#secret-scope-theft--databricks-backed-and-key-vault-backed-scopes` | Secret-scope theft — Databricks-backed and Key Vault-backed scopes |  | EXCLUDED | Databricks ACLs, not Azure RBAC; entry point azure-databricks-assign-workspace-admin. |
| `az-privilege-escalation/az-databricks-privesc.md#unity-catalog-storage-credential--external-location-abuse` | Unity Catalog storage-credential / external-location abuse |  | EXCLUDED | NEEDS SCHEMA: a storage credential or external location can confer additional Unity Catalog or backing storage authority, but the exact caller, resource grant, and before/after effective permissions are not verified. |
| `az-privilege-escalation/az-databricks-privesc.md#microsoftdatabricksaccessconnectorswrite--attach-an-over-privileged-managed-identity` | `Microsoft.Databricks/accessConnectors/write` — attach an over-privileged managed identity | Microsoft.Authorization/roleAssignments/write,Microsoft.Databricks/accessConnectors/write,Microsoft.ManagedIdentity/userAssignedIdentities/*/assign/action | EXCLUDED | Using the connector identity needs Unity Catalog storage-credential privileges outside Azure RBAC. |
| `az-privilege-escalation/az-databricks-privesc.md#the-managed-rg-deny-assignment-and-why-updatedenyassignment-is-not-an-attacker-primitive` | The managed-RG deny assignment (and why `updateDenyAssignment` is NOT an attacker primitive) |  | EXCLUDED | Page states it is not an attacker primitive. |

## az-privilege-escalation/az-defender-for-cloud-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-defender-for-cloud-privesc.md#az---defender-for-cloud-privesc` | Az - Defender for Cloud Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-defender-for-cloud-privesc.md#defender-for-cloud` | Defender for Cloud |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-defender-for-cloud-privesc.md#microsoftsecurityautomationswrite--abuse-the-workflow-automation-identity` | `Microsoft.Security/automations/write` — abuse the workflow-automation identity | Microsoft.Security/automations/write | EXCLUDED | Identity gain needs Microsoft.Logic/workflows/write on the target Logic App; covered by azure-logicapp-workflow-write-existing-identity. |
| `az-privilege-escalation/az-defender-for-cloud-privesc.md#deployifnotexists-remediation-identities-via-azure-policy` | DeployIfNotExists remediation identities (via Azure Policy) |  | EXCLUDED | Definition-rewrite branch NEEDS SCHEMA for exact assignment-to-MI join and observed remediation; assignment-write branch is separate. |
| `az-privilege-escalation/az-defender-for-cloud-privesc.md#microsoftsecuritypricings--connector-service-principals` | `Microsoft.Security/pricings` + connector service principals | Microsoft.Security/pricings | EXCLUDED | Entra application credential paths (Entra ID catalog scope). |
| `az-privilege-escalation/az-defender-for-cloud-privesc.md#references` | References |  | STRUCTURAL | references |

## az-privilege-escalation/az-dev-center-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-dev-center-privesc.md#az---dev-center-deployment-environments--dev-box-privesc` | Az - Dev Center (Deployment Environments & Dev Box) Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-dev-center-privesc.md#dev-center` | Dev Center |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-dev-center-privesc.md#dev-center-overview` | Dev Center overview |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-dev-center-privesc.md#ade-deployment-identity-template-injection-marquee-privesc` | ADE deployment-identity template injection (marquee privesc) | Microsoft.DevCenter/projects/users/environments/userWrite/action | EXCLUDED | NEEDS SCHEMA: Environment deployment permission does not prove attacker control of the selected ADE template, successful deployment, or execution under its deployment identity. |
| `az-privilege-escalation/az-dev-center-privesc.md#catalog-poisoning-supply-chain` | Catalog poisoning (supply chain) | Microsoft.DevCenter/*,Microsoft.DevCenter/projects/* | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-dev-center-privesc.md#ade-deployment-identity-template-injection-marquee-privesc` |
| `az-privilege-escalation/az-dev-center-privesc.md#dev-box-local-admin-cloud-pc--customization-rce` | Dev Box local-admin Cloud PC + customization RCE | Microsoft.DevCenter/projects/users/devboxes/userWrite/action | EXCLUDED | Dev boxes carry no documented Azure managed identity; gain is local admin on a Cloud PC. |
| `az-privilege-escalation/az-dev-center-privesc.md#references` | References |  | STRUCTURAL | references/enumeration |

## az-privilege-escalation/az-devtest-labs-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-devtest-labs-privesc.md#az---devtest-labs-privesc` | Az - DevTest Labs Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-devtest-labs-privesc.md#devtest-labs` | DevTest Labs |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-devtest-labs-privesc.md#devtest-labs-overview` | DevTest Labs overview |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-devtest-labs-privesc.md#applyartifacts--in-guest-rce--managed-identity-theft-marquee` | ApplyArtifacts → in-guest RCE + managed-identity theft (marquee) | Microsoft.DevTestLab/labs/virtualMachines/applyArtifacts/action | MAPPED | `azure-devtestlabs-apply-artifacts` |
| `az-privilege-escalation/az-devtest-labs-privesc.md#claim--claimanyvm--seize-ownership-of-a-pooled-vm` | Claim / ClaimAnyVm → seize ownership of a pooled VM | Microsoft.DevTestLab/labs/claimAnyVm/action,Microsoft.DevTestLab/labs/virtualMachines/claim/action | EXCLUDED | NEEDS SCHEMA: Lab claim permission does not prove a particular VM is unclaimed/claimable, source login or artifact access, and exact managed-identity token/new action. |
| `az-privilege-escalation/az-devtest-labs-privesc.md#foothold-vms-schedules--policy-tampering` | Foothold VMs, schedules & policy tampering | Microsoft.DevTestLab/labs/policySets/policies/write,Microsoft.DevTestLab/labs/schedules/write,Microsoft.DevTestLab/labs/virtualMachines/write,Microsoft.DevTestLab/labs/write | EXCLUDED | Persistence or DoS; no identity beyond the modelled artifact and claim paths. |
| `az-privilege-escalation/az-devtest-labs-privesc.md#pivot-to-raw-compute` | Pivot to raw Compute |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputevirtualmachinesextensionswrite`, `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputevirtualmachinesruncommandaction` |
| `az-privilege-escalation/az-devtest-labs-privesc.md#references` | References |  | STRUCTURAL | references/enumeration |

## az-privilege-escalation/az-digital-twins-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-digital-twins-privesc.md#az---digital-twins-privesc` | Az - Digital Twins Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-digital-twins-privesc.md#azure-digital-twins` | Azure Digital Twins |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-digital-twins-privesc.md#microsoftdigitaltwinsqueryaction` | `Microsoft.DigitalTwins/query/action` | Microsoft.DigitalTwins/query/action | EXCLUDED | Data read. |
| `az-privilege-escalation/az-digital-twins-privesc.md#microsoftdigitaltwinsdigitaltwinsread` | `Microsoft.DigitalTwins/digitaltwins/read` | Microsoft.DigitalTwins/digitaltwins/read | EXCLUDED | Data read. |
| `az-privilege-escalation/az-digital-twins-privesc.md#microsoftdigitaltwinsdigitaltwinswrite` | `Microsoft.DigitalTwins/digitaltwins/write` | Microsoft.DigitalTwins/digitaltwins/write | EXCLUDED | Graph data read/write; write is a second-order, consumer-dependent effect without a modelable identity edge. |
| `az-privilege-escalation/az-digital-twins-privesc.md#microsoftdigitaltwinsdigitaltwinsrelationshipsread` | `Microsoft.DigitalTwins/digitaltwins/relationships/read` | Microsoft.DigitalTwins/digitaltwins/relationships/read | EXCLUDED | Data read. |
| `az-privilege-escalation/az-digital-twins-privesc.md#microsoftdigitaltwinsdigitaltwinsinstancesendpointswrite--microsoftdigitaltwinseventrouteswrite--live-telemetrygraph-exfil` | `Microsoft.DigitalTwins/digitalTwinsInstances/endpoints/write` + `Microsoft.DigitalTwins/eventroutes/write` — live telemetry/graph exfil | Microsoft.DigitalTwins/digitalTwinsInstances/endpoints/write,Microsoft.DigitalTwins/eventroutes/write | EXCLUDED | Telemetry and graph exfiltration; no identity. |
| `az-privilege-escalation/az-digital-twins-privesc.md#microsoftdigitaltwinsdigitaltwinsinstanceswrite--managed-identity-attach-confused-deputy-foothold` | `Microsoft.DigitalTwins/digitalTwinsInstances/write` — managed-identity attach (confused-deputy foothold) | Microsoft.DigitalTwins/digitalTwinsInstances/write | EXCLUDED | `azure-digitaltwins-assign-identity-import` NEEDS SCHEMA: exact bounded credential or workload execution to a named target and newly authorized action are unverified. |
| `az-privilege-escalation/az-digital-twins-privesc.md#microsoftdigitaltwinsjobsimportswrite--bulk-graph-import-mass-poisoning--mi-confused-deputy-read` | `Microsoft.DigitalTwins/jobs/imports/write` — bulk graph import (mass poisoning + MI confused-deputy read) | Microsoft.DigitalTwins/jobs/imports/write | EXCLUDED | `azure-digitaltwins-import-job-identity-read` NEEDS SCHEMA: exact bounded credential or workload execution to a named target and newly authorized action are unverified. |
| `az-privilege-escalation/az-digital-twins-privesc.md#graph--schema-integrity-writes--modelswrite-digitaltwinsrelationshipswrite-digitaltwinscommandsaction` | Graph & schema integrity writes — `models/write`, `digitaltwins/relationships/write`, `digitaltwins/commands/action` | Microsoft.DigitalTwins/digitaltwins/commands/action,Microsoft.DigitalTwins/digitaltwins/relationships/write,Microsoft.DigitalTwins/models/write | EXCLUDED | Data integrity impact on downstream consumers; no identity. |
| `az-privilege-escalation/az-digital-twins-privesc.md#references` | References |  | STRUCTURAL | section/how-to heading; no technique |

## az-privilege-escalation/az-entra-id-governance-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-entra-id-governance-privesc.md#az---entra-id-governance-entitlement-management-privesc` | Az - Entra ID Governance (Entitlement Management) Privesc |  | STRUCTURAL | title/reference/intro heading |
| `az-privilege-escalation/az-entra-id-governance-privesc.md#entra-id-governance` | Entra ID Governance |  | EXCLUDED | Introductory text. |
| `az-privilege-escalation/az-entra-id-governance-privesc.md#entitlement-management-overview` | Entitlement Management overview |  | EXCLUDED | Explanatory text. |
| `az-privilege-escalation/az-entra-id-governance-privesc.md#catalog-scoped-self-grant-privesc` | Catalog-scoped self-grant (privesc) |  | MAPPED | `azure-entraid-entitlement-catalog-self-grant-group` `azure-entraid-entitlement-catalog-self-grant-role` |
| `az-privilege-escalation/az-entra-id-governance-privesc.md#guest-self-enrolment-via-loose-auto-assignment-rule-privesc` | Guest self-enrolment via loose auto-assignment rule (privesc) |  | EXCLUDED | Selector cannot prove the invited guest satisfies the exact policy rule or receives the named permissions. |
| `az-privilege-escalation/az-entra-id-governance-privesc.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-privilege-escalation/az-entraid-privesc/README.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-entraid-privesc/README.md#az---entraid-privesc` | Az - EntraID Privesc |  | STRUCTURAL | title/reference/intro heading |
| `az-privilege-escalation/az-entraid-privesc/README.md#entra-id-azuread--azure-iam` | Entra ID (AzureAD) & Azure IAM |  | EXCLUDED | Introductory text; techniques are mapped heading by heading. |
| `az-privilege-escalation/az-entraid-privesc/README.md#microsoft-graph-application-permissions` | Microsoft Graph application permissions |  | STRUCTURAL | section header grouping technique sub-headings |
| `az-privilege-escalation/az-entraid-privesc/README.md#applicationreadwriteall` | `Application.ReadWrite.All` |  | MAPPED | `azure-entraid-graph-application-readwrite-all` |
| `az-privilege-escalation/az-entraid-privesc/README.md#approleassignmentreadwriteall` | `AppRoleAssignment.ReadWrite.All` |  | MAPPED | `azure-entraid-graph-approleassignment-readwrite-all` |
| `az-privilege-escalation/az-entraid-privesc/README.md#delegatedpermissiongrantreadwriteall` | `DelegatedPermissionGrant.ReadWrite.All` |  | EXCLUDED | Creating consent alone does not give the source a target-user token; a bound victim sign-in is required but not verified. |
| `az-privilege-escalation/az-entraid-privesc/README.md#rolemanagementreadwritedirectory` | `RoleManagement.ReadWrite.Directory` |  | MAPPED | `azure-entraid-graph-rolemanagement-readwrite-directory` |
| `az-privilege-escalation/az-entraid-privesc/README.md#userauthenticationmethodreadwriteall` | `UserAuthenticationMethod.ReadWrite.All` |  | MAPPED | `azure-entraid-graph-userauthenticationmethod-tap` |
| `az-privilege-escalation/az-entraid-privesc/README.md#pim-application-permissions` | PIM application permissions |  | EXCLUDED | Legacy PIM (iteration 2) permissions on retired APIs; current directory-role PIM schedule APIs require RoleManagement.ReadWrite.Directory, modelled in azure-entraid-graph-rolemanagement-readwrite-directory. |
| `az-privilege-escalation/az-entraid-privesc/README.md#sensitive-graph-permissions` | Sensitive Graph permissions |  | MAPPED | `azure-entraid-graph-group-readwrite-all` |
| `az-privilege-escalation/az-entraid-privesc/README.md#other-high-impact-microsoft-graph-permissions-directoryreadwriteall-groupmemberreadwriteall-synchronizationreadwriteall-privilegedeligibilityschedulereadwriteazureadgroup` | Other high-impact Microsoft Graph permissions (`Directory.ReadWrite.All`, `GroupMember.ReadWrite.All`, `Synchronization.ReadWrite.All`, `PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup`) |  | MAPPED | `azure-entraid-graph-pim-groups-eligibility` |
| `az-privilege-escalation/az-entraid-privesc/README.md#roles` | Roles |  | STRUCTURAL | section header grouping technique sub-headings |
| `az-privilege-escalation/az-entraid-privesc/README.md#role-privileged-role-administrator` | Role: Privileged Role Administrator <a href="#c9d4cde0-7dcc-45d5-aa95-59d198ae84b2" id="c9d4cde0-7dcc-45d5-aa95-59d198ae84b2"></a> |  | MAPPED | `azure-entraid-role-assignment-manage` `azure-entraid-custom-role-definition-update` |
| `az-privilege-escalation/az-entraid-privesc/README.md#applications` | Applications |  | STRUCTURAL | section header grouping technique sub-headings |
| `az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectoryapplicationscredentialsupdate` | `microsoft.directory/applications/credentials/update` |  | MAPPED | `azure-entraid-app-credentials-update` |
| `az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectoryapplicationsmyorganizationallpropertiesupdate` | `microsoft.directory/applications.myOrganization/allProperties/update` |  | MAPPED | `azure-entraid-app-myorg-credentials-update` |
| `az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectoryapplicationsmyorganizationcredentialsupdate` | `microsoft.directory/applications.myOrganization/credentials/update` |  | EXCLUDED | Modelled in azure-entraid-app-myorg-credentials-update (single-tenant applications). |
| `az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectoryapplicationsownersupdate` | `microsoft.directory/applications/owners/update` |  | MAPPED | `azure-entraid-app-owners-update` `azure-entraid-app-owner-credentials` |
| `az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectoryapplicationsallpropertiesupdate` | `microsoft.directory/applications/allProperties/update` |  | EXCLUDED | Token interception via added redirect URI requires victim interaction and an exploitable auth flow (code redemption needs client secret/PKCE); requested permissions still need fresh consent. The credential-update part of allProperties/update is modelled in azure-entraid-app-credentials-update. |
| `az-privilege-escalation/az-entraid-privesc/README.md#applications-privilege-escalation` | Applications Privilege Escalation |  | EXCLUDED | Explanatory/enumeration section; the underlying credential-injection edge is modelled by the application/service-principal credential entries. |
| `az-privilege-escalation/az-entraid-privesc/README.md#service-principals` | Service Principals |  | STRUCTURAL | section header grouping technique sub-headings |
| `az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectoryserviceprincipalscredentialsupdate` | `microsoft.directory/servicePrincipals/credentials/update` |  | MAPPED | `azure-entraid-sp-credentials-update` |
| `az-privilege-escalation/az-entraid-privesc/README.md#entra-agent-id-blueprint-credential-abuse-agentidentityblueprintaddremovecredsall` | Entra Agent ID blueprint credential abuse (`AgentIdentityBlueprint.AddRemoveCreds.All`) |  | MAPPED | `azure-entraid-agent-blueprint-credentials` |
| `az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectoryserviceprincipalssynchronizationcredentialsmanage` | `microsoft.directory/servicePrincipals/synchronizationCredentials/manage` |  | EXCLUDED | Manages provisioning-connector credentials, not the service principal's own sign-in credentials; impact depends on the external connector target and yields no Entra principal. |
| `az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectoryserviceprincipalsownersupdate` | `microsoft.directory/servicePrincipals/owners/update` |  | MAPPED | `azure-entraid-sp-owners-update` `azure-entraid-sp-owner-credentials` |
| `az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectoryserviceprincipalsdisable-and-enable` | `microsoft.directory/servicePrincipals/disable` and `enable` |  | EXCLUDED | Availability/DoS or re-enabling a principal whose credentials are already controlled; grants no new identity by itself. |
| `az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectoryserviceprincipalsgetpasswordsinglesignoncredentials--microsoftdirectoryserviceprincipalsmanagepasswordsinglesignoncredentials` | `microsoft.directory/servicePrincipals/getPasswordSingleSignOnCredentials` & `microsoft.directory/servicePrincipals/managePasswordSingleSignOnCredentials` |  | EXCLUDED | Reads/sets credentials for third-party password-SSO applications; access is to external apps, not to an Entra or Azure principal. |
| `az-privilege-escalation/az-entraid-privesc/README.md#groups` | Groups |  | STRUCTURAL | section header grouping technique sub-headings |
| `az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectorygroupsallpropertiesupdate` | `microsoft.directory/groups/allProperties/update` |  | EXCLUDED | Membership write is modelled in azure-entraid-group-members-update and membership-rule write in azure-entraid-group-dynamic-rule-update. |
| `az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectorygroupsownersupdate` | `microsoft.directory/groups/owners/update` |  | MAPPED | `azure-entraid-group-owners-update` |
| `az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectorygroupsmembersupdate` | `microsoft.directory/groups/members/update` |  | MAPPED | `azure-entraid-group-members-update` |
| `az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectorygroupsdynamicmembershipruleupdate` | `microsoft.directory/groups/dynamicMembershipRule/update` |  | MAPPED | `azure-entraid-group-dynamic-rule-update` |
| `az-privilege-escalation/az-entraid-privesc/README.md#dynamic-groups-privesc` | Dynamic Groups Privesc |  | EXCLUDED | Pointer to dynamic-groups.md; dynamic-group rule mutation is modelled separately; source-controlled rule satisfaction is not yet verified. |
| `az-privilege-escalation/az-entraid-privesc/README.md#users` | Users |  | STRUCTURAL | section header grouping technique sub-headings |
| `az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectoryuserspasswordupdate` | `microsoft.directory/users/password/update` |  | MAPPED | `azure-entraid-reset-password-password-admin` `azure-entraid-reset-password-helpdesk-admin` `azure-entraid-reset-credentials-authentication-admin` `azure-entraid-reset-password-user-admin` `azure-entraid-reset-password-partner-tier1` `azure-entraid-reset-credentials-privileged-auth-admin` |
| `az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectoryusersbasicupdate` | `microsoft.directory/users/basic/update` |  | EXCLUDED | Source-controlled rule satisfaction is not yet verified. |
| `az-privilege-escalation/az-entraid-privesc/README.md#conditional-access-policies--mfa-bypass` | Conditional Access Policies & MFA bypass |  | EXCLUDED | Pointer to az-conditional-access-policies-mfa-bypass.md; bypasses are access techniques, not privilege gain. |
| `az-privilege-escalation/az-entraid-privesc/README.md#devices` | Devices |  | STRUCTURAL | section header grouping technique sub-headings |
| `az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectorydevicesregisteredownersupdate` | `microsoft.directory/devices/registeredOwners/update` |  | EXCLUDED | Directory metadata only; does not grant device or identity access by itself (HackTricks notes this). |
| `az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectorydevicesregisteredusersupdate` | `microsoft.directory/devices/registeredUsers/update` |  | EXCLUDED | Same as devices/registeredOwners: device registration links do not grant the device identity or its local admin rights; no principal edge. |
| `az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectorydevicelocalcredentialspasswordread` | `microsoft.directory/deviceLocalCredentials/password/read` |  | EXCLUDED | Credential read for local device administrator accounts; no Entra/Azure principal target kind (device-plane lateral movement). |
| `az-privilege-escalation/az-entraid-privesc/README.md#bitlockerkeys` | BitlockerKeys |  | STRUCTURAL | section header grouping technique sub-headings |
| `az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectorybitlockerkeyskeyread` | `microsoft.directory/bitlockerKeys/key/read` |  | EXCLUDED | Data access (volume unlock); no identity gain. |
| `az-privilege-escalation/az-entraid-privesc/README.md#administrative-unit-scoped-role-assignment-stealth-privilege-source` | Administrative-unit-scoped role assignment (stealth privilege source) |  | EXCLUDED | Creating the assignment needs role-assignment management (azure-entraid-role-assignment-manage / azure-entraid-graph-rolemanagement-readwrite-directory); the resulting AU-scoped holders are evaluated by the reset entries through entra_role_assignment_scope_covers_target. |
| `az-privilege-escalation/az-entraid-privesc/README.md#custom-security-attributes-feeding-abac--dynamic-membership` | Custom security attributes feeding ABAC / dynamic membership |  | EXCLUDED | The evaluator has not proved the source can set a value satisfying the exact ABAC expression, so neither the data-plane nor role-assignment permission gain is established. |
| `az-privilege-escalation/az-entraid-privesc/README.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-privilege-escalation/az-entraid-privesc/az-conditional-access-policies-mfa-bypass.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-entraid-privesc/az-conditional-access-policies-mfa-bypass.md#az---conditional-access-policies--mfa-bypass` | Az - Conditional Access Policies & MFA Bypass |  | STRUCTURAL | title/reference/intro heading |
| `az-privilege-escalation/az-entraid-privesc/az-conditional-access-policies-mfa-bypass.md#entra-id-azuread--azure-iam` | Entra ID (AzureAD) & Azure IAM |  | STRUCTURAL | title/reference/intro heading |
| `az-privilege-escalation/az-entraid-privesc/az-conditional-access-policies-mfa-bypass.md#basic-information` | Basic Information |  | STRUCTURAL | title/reference/intro heading |
| `az-privilege-escalation/az-entraid-privesc/az-conditional-access-policies-mfa-bypass.md#enumeration` | Enumeration |  | STRUCTURAL | title/reference/intro heading |
| `az-privilege-escalation/az-entraid-privesc/az-conditional-access-policies-mfa-bypass.md#policyreadall--policyreadwriteconditionalaccess` | `Policy.Read.All` + `Policy.ReadWrite.ConditionalAccess` |  | EXCLUDED | Weakens or disables Conditional Access (defense evasion); grants no principal's privileges. Belongs to Least Privilege / Exposure. |
| `az-privilege-escalation/az-entraid-privesc/az-conditional-access-policies-mfa-bypass.md#conditional-access-policies-bypasses` | Conditional Access Policies Bypasses |  | EXCLUDED | Authentication-control bypass for an already-compromised credential; no new principal privileges. |
| `az-privilege-escalation/az-entraid-privesc/az-conditional-access-policies-mfa-bypass.md#device-platforms---device-condition` | Device Platforms - Device Condition |  | SUBSECTION | of #conditional-access-policies-bypasses: EXCLUDED: Authentication-control bypass for an already-compromised credential; no new principal privileges. |
| `az-privilege-escalation/az-entraid-privesc/az-conditional-access-policies-mfa-bypass.md#locations-countries-ip-ranges---device-condition` | Locations: Countries, IP ranges - Device Condition |  | SUBSECTION | of #conditional-access-policies-bypasses: EXCLUDED: Authentication-control bypass for an already-compromised credential; no new principal privileges. |
| `az-privilege-escalation/az-entraid-privesc/az-conditional-access-policies-mfa-bypass.md#cloud-apps` | Cloud Apps |  | SUBSECTION | of #conditional-access-policies-bypasses: EXCLUDED: Authentication-control bypass for an already-compromised credential; no new principal privileges. |
| `az-privilege-escalation/az-entraid-privesc/az-conditional-access-policies-mfa-bypass.md#other-az-mfa-bypasses` | Other Az MFA Bypasses |  | EXCLUDED | MFA bypass for existing credentials, configuration-dependent and partly legacy; not a permission-based escalation edge. |
| `az-privilege-escalation/az-entraid-privesc/az-conditional-access-policies-mfa-bypass.md#ring-tone` | Ring tone |  | SUBSECTION | of #other-az-mfa-bypasses: EXCLUDED: MFA bypass for existing credentials, configuration-dependent and partly legacy; not a permission-based escalation edge. |
| `az-privilege-escalation/az-entraid-privesc/az-conditional-access-policies-mfa-bypass.md#compliant-devices` | Compliant Devices |  | SUBSECTION | of #other-az-mfa-bypasses: EXCLUDED: MFA bypass for existing credentials, configuration-dependent and partly legacy; not a permission-based escalation edge. |
| `az-privilege-escalation/az-entraid-privesc/az-conditional-access-policies-mfa-bypass.md#tooling` | Tooling |  | EXCLUDED | Tooling for CA/MFA gap testing; no privilege edge. |
| `az-privilege-escalation/az-entraid-privesc/az-conditional-access-policies-mfa-bypass.md#azureappssweep` | [**AzureAppsSweep**](https://github.com/carlospolop/AzureAppsSweep) |  | SUBSECTION | of #tooling: EXCLUDED: Tooling for CA/MFA gap testing; no privilege edge. |
| `az-privilege-escalation/az-entraid-privesc/az-conditional-access-policies-mfa-bypass.md#roadrecon` | [roadrecon](https://github.com/dirkjanm/ROADtools) |  | SUBSECTION | of #tooling: EXCLUDED: Tooling for CA/MFA gap testing; no privilege edge. |
| `az-privilege-escalation/az-entraid-privesc/az-conditional-access-policies-mfa-bypass.md#invoke-mfasweep` | [Invoke-MFASweep](https://github.com/dafthack/MFASweep) |  | SUBSECTION | of #tooling: EXCLUDED: Tooling for CA/MFA gap testing; no privilege edge. |
| `az-privilege-escalation/az-entraid-privesc/az-conditional-access-policies-mfa-bypass.md#ropci` | [ROPCI](https://github.com/wunderwuzzi23/ropci) |  | SUBSECTION | of #tooling: EXCLUDED: Tooling for CA/MFA gap testing; no privilege edge. |
| `az-privilege-escalation/az-entraid-privesc/az-conditional-access-policies-mfa-bypass.md#donkeytoken` | [donkeytoken](https://github.com/silverhack/donkeytoken) |  | SUBSECTION | of #tooling: EXCLUDED: Tooling for CA/MFA gap testing; no privilege edge. |
| `az-privilege-escalation/az-entraid-privesc/az-conditional-access-policies-mfa-bypass.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-privilege-escalation/az-entraid-privesc/az-connect-health-abuse.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-entraid-privesc/az-connect-health-abuse.md#az---entra-connect-health-abuse-microsoftadhybridhealthservice` | Az - Entra Connect Health Abuse (`Microsoft.ADHybridHealthService`) |  | STRUCTURAL | title/reference/intro heading |
| `az-privilege-escalation/az-entraid-privesc/az-connect-health-abuse.md#entra-id-azuread--azure-iam` | Entra ID (AzureAD) & Azure IAM |  | STRUCTURAL | title/reference/intro heading |
| `az-privilege-escalation/az-entraid-privesc/az-connect-health-abuse.md#forged-ad-fs-sign-in-log-injection-fake-agent` | Forged AD FS sign-in log injection (fake agent) |  | EXCLUDED | Log forgery / defense evasion; does not grant any identity or permission. |
| `az-privilege-escalation/az-entraid-privesc/az-connect-health-abuse.md#on-prem-agentkey-theft-from-an-ad-fs-host--event-replay` | On-prem `AgentKey` theft from an AD FS host → event replay |  | EXCLUDED | Starts from on-prem host compromise and only yields log injection; no cloud principal edge. |
| `az-privilege-escalation/az-entraid-privesc/az-connect-health-abuse.md#hybrid-recon-on-prem-identity-leakage-via-connect-health-reader` | Hybrid recon: on-prem identity leakage via Connect Health (reader) |  | EXCLUDED | Reconnaissance / information disclosure only (the page notes the AgentKey-from-reader path was remediated). |
| `az-privilege-escalation/az-entraid-privesc/az-connect-health-abuse.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-privilege-escalation/az-entraid-privesc/dynamic-groups.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-entraid-privesc/dynamic-groups.md#az---dynamic-groups-privesc` | Az - Dynamic Groups Privesc |  | STRUCTURAL | title/reference/intro heading |
| `az-privilege-escalation/az-entraid-privesc/dynamic-groups.md#entra-id-azuread--azure-iam` | Entra ID (AzureAD) & Azure IAM |  | STRUCTURAL | title/reference/intro heading |
| `az-privilege-escalation/az-entraid-privesc/dynamic-groups.md#basic-information` | Basic Information |  | STRUCTURAL | title/reference/intro heading |
| `az-privilege-escalation/az-entraid-privesc/dynamic-groups.md#privesc` | Privesc |  | EXCLUDED | Current selector treats any dynamic membership rule as satisfiable; source-controlled attributes and exact rule outcome are not verified. |
| `az-privilege-escalation/az-entraid-privesc/dynamic-groups.md#dynamic-groups-enumeration` | Dynamic Groups Enumeration |  | EXCLUDED | Enumeration only; escalation is modelled in entraid_groups.yaml. |
| `az-privilege-escalation/az-entraid-privesc/dynamic-groups.md#example` | Example |  | STRUCTURAL | title/reference/intro heading |
| `az-privilege-escalation/az-entraid-privesc/dynamic-groups.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-privilege-escalation/az-event-grid-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-event-grid-privesc.md#az---event-grid-privesc` | Az - Event Grid Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-event-grid-privesc.md#event-grid` | Event Grid |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-event-grid-privesc.md#shared-access-key-disclosure-and-event-injection` | Shared-access key disclosure and event injection |  | EXCLUDED | `azure-eventgrid-event-injection-consumer` NEEDS SCHEMA: exact written object or message, consumer binding and trigger, observed execution, and a newly obtained identity token or action are unverified. |
| `az-privilege-escalation/az-event-grid-privesc.md#namespace-event-injection-with-only-eventssendaction` | Namespace event injection with only `events/send/action` |  | EXCLUDED | Message injection; escalation depends on downstream consumer logic, not modelable from RBAC. |
| `az-privilege-escalation/az-event-grid-privesc.md#mqtt-topic-space-publication-and-subscription` | MQTT topic-space publication and subscription |  | EXCLUDED | Message read/injection. |
| `az-privilege-escalation/az-event-grid-privesc.md#secret-delivery-attribute-disclosure` | Secret delivery-attribute disclosure |  | EXCLUDED | Secret read of unknown content. |
| `az-privilege-escalation/az-event-grid-privesc.md#signed-event-subscription-endpoint-disclosure` | Signed event-subscription endpoint disclosure |  | EXCLUDED | Callback secret read (invokes triggers only). |
| `az-privilege-escalation/az-event-grid-privesc.md#hijack-event-delivery-by-overwriting-a-subscription-with-eventsubscriptionswrite` | Hijack event delivery by overwriting a subscription with `eventSubscriptions/write` |  | EXCLUDED | Event exfiltration; any delivery token is audience-bound to the destination app, not a usable Azure identity edge. |
| `az-privilege-escalation/az-event-grid-privesc.md#namespace-pull-subscription-data-disclosure` | Namespace pull-subscription data disclosure |  | EXCLUDED | Data read. |
| `az-privilege-escalation/az-event-grid-privesc.md#subscribe-to-azure-platformresource-events-with-systemtopicseventsubscriptionswrite` | Subscribe to Azure platform/resource events with `systemTopics/eventSubscriptions/write` |  | EXCLUDED | Event feed exfiltration; no identity. |
| `az-privilege-escalation/az-event-grid-privesc.md#backdoor-mqtt-client-via-namespacesclients--clientgroups--permissionbindingswrite` | Backdoor MQTT client via `namespaces/clients` + `clientGroups` + `permissionBindings/write` | Microsoft.EventGrid/namespaces/clients/write,Microsoft.EventGrid/namespaces/clientGroups/write,Microsoft.EventGrid/namespaces/permissionBindings/write | MAPPED | `azure-eventgrid-mqtt-client-grant-external-principal` requires exact client, usable credential, group and permission binding, prior denial, and newly allowed topic action; historical broad entry remains excluded. |
| `az-privilege-escalation/az-event-grid-privesc.md#authnetwork-downgrade-with-namespaceswrite-topicswrite-domainswrite` | Auth/network downgrade with `namespaces/write`, `topics/write`, `domains/write` |  | EXCLUDED | Posture downgrade; no identity. |

## az-privilege-escalation/az-event-hubs-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-event-hubs-privesc.md#az---event-hubs-privesc` | Az - Event Hubs Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-event-hubs-privesc.md#event-hubs` | Event Hubs |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-event-hubs-privesc.md#authorization-rule-key-disclosure` | Authorization-rule key disclosure |  | EXCLUDED | NEEDS SCHEMA: bind the named Event Hubs authorization rule, returned SAS key, enabled local auth, successful key use, and a Send/Listen/Manage capability the caller lacked before key recovery. |
| `az-privilege-escalation/az-event-hubs-privesc.md#direct-entra-authenticated-event-read-and-injection` | Direct Entra-authenticated event read and injection |  | EXCLUDED | Moved to post-exploitation; Strict principal-boundary audit: The declared target is a bounded authority rather than an identified target principal or an explicit grant of extra permissions to the caller. |
| `az-privilege-escalation/az-event-hubs-privesc.md#create-an-entity-sas-policy-and-recover-its-generated-key` | Create an entity SAS policy and recover its generated key |  | EXCLUDED | NEEDS SCHEMA: prove the exact new entity SAS rule, its rights, returned key, successful use, and a new effective permission absent from the caller before rule creation. |
| `az-privilege-escalation/az-event-hubs-privesc.md#geo-disaster-recovery-alias-key-disclosure` | Geo-Disaster Recovery alias key disclosure |  | EXCLUDED | NEEDS SCHEMA: bind the exact Geo-DR alias rule and returned SAS key to successful use and new effective rights absent from the caller. |

## az-privilege-escalation/az-fabric-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-fabric-privesc.md#az---microsoft-fabric-privesc` | Az - Microsoft Fabric Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-fabric-privesc.md#microsoft-fabric` | Microsoft Fabric |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-fabric-privesc.md#notebook--spark-job-rce-as-the-submitting-identity--token--key-vault-theft` | Notebook / Spark Job RCE as the submitting identity (+ token & Key Vault theft) |  | EXCLUDED | `azure-fabric-notebook-workspace-identity` NEEDS SCHEMA: exact execution or token retrieval for a named identity and a newly authorized action are unverified. |
| `az-privilege-escalation/az-fabric-privesc.md#fabric-administrator-entra--tenant-takeover--org-wide-scanner-recon` | Fabric Administrator (Entra) — tenant takeover + org-wide scanner recon |  | EXCLUDED | `azure-fabric-administrator-workspace-identity` NEEDS SCHEMA: exact execution or token retrieval for a named identity and a newly authorized action are unverified. |
| `az-privilege-escalation/az-fabric-privesc.md#connection--gateway-credential-confused-deputy-exfil` | Connection / gateway credential confused-deputy exfil |  | EXCLUDED | NEEDS SCHEMA: a Fabric connection or gateway may convey exact Fabric or downstream data-source authority, but the caller, target connection identity, usable access, and new effective permission are not verified. |
| `az-privilege-escalation/az-fabric-privesc.md#references` | References |  | STRUCTURAL | section/how-to heading; no technique |

## az-privilege-escalation/az-fluid-relay-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-fluid-relay-privesc.md#az---fluid-relay-privesc` | Az - Fluid Relay Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-fluid-relay-privesc.md#fluid-relay` | Fluid Relay |  | EXCLUDED | Page title / introduction heading; no technique. |
| `az-privilege-escalation/az-fluid-relay-privesc.md#server-tenant-key-disclosure-and-regeneration` | Server tenant-key disclosure and regeneration | Microsoft.FluidRelay/fluidRelayServers/listKeys/action | EXCLUDED | NEEDS SCHEMA: Exact Fluid tenant/subject, usable key-derived token, and new application permission must be verified. |
| `az-privilege-escalation/az-fluid-relay-privesc.md#container-id-enumeration-with-fluidrelaycontainersread` | Container-ID enumeration with `fluidRelayContainers/read` | Microsoft.FluidRelay/fluidRelayServers/fluidRelayContainers/read | STRUCTURAL | pointer to post-exploitation page |
| `az-privilege-escalation/az-fluid-relay-privesc.md#cmkidentity-tamper-with-fluidrelayserverswrite` | CMK/identity tamper with `fluidRelayServers/write` | Microsoft.FluidRelay/fluidRelayServers/write | STRUCTURAL | pointer to post-exploitation page |

## az-privilege-escalation/az-functions-app-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-functions-app-privesc.md#az---functions-app-privesc` | Az - Functions App Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-functions-app-privesc.md#function-apps` | Function Apps |  | STRUCTURAL | section grouping heading; techniques are its subsections |
| `az-privilege-escalation/az-functions-app-privesc.md#storage-backed-deployment-content` | Storage-backed deployment content | Microsoft.Storage/storageAccounts/listKeys/action | EXCLUDED | NEEDS SCHEMA: The exact Function App content-storage resource binding is not collected; storage write alone cannot prove code overwrite, accepted execution, or access to the app managed identity. |
| `az-privilege-escalation/az-functions-app-privesc.md#microsoftwebsiteshostlistkeysaction-and-microsoftwebsitesslotshostlistkeysaction` | `Microsoft.Web/sites/host/listkeys/action` and `Microsoft.Web/sites/slots/host/listkeys/action` | Microsoft.Web/sites/host/listkeys/action,Microsoft.Web/sites/slots/host/listkeys/action | EXCLUDED | NEEDS SCHEMA: Host master key read alone does not prove control of function code, execution as the named app identity, or a usable MI token/new action. |
| `az-privilege-escalation/az-functions-app-privesc.md#microsoftwebsitesfunctionsmasterkeyread` | `Microsoft.Web/sites/functions/masterkey/read` | Microsoft.Web/sites/functions/masterkey/read | EXCLUDED | NEEDS SCHEMA: Master-key read alone does not prove an exact executable function or source ability to obtain a usable managed-identity token. |
| `az-privilege-escalation/az-functions-app-privesc.md#microsoftwebsitesfunctionslistkeysaction-and-microsoftwebsitesslotsfunctionslistkeysaction` | `Microsoft.Web/sites/functions/listkeys/action` and `Microsoft.Web/sites/slots/functions/listkeys/action` | Microsoft.Web/sites/functions/listkeys/action,Microsoft.Web/sites/slots/functions/listkeys/action | EXCLUDED | A function key only authorizes invoking one function; no code execution or identity gain. |
| `az-privilege-escalation/az-functions-app-privesc.md#microsoftwebsitesfunctionskeyswrite-and-microsoftwebsitesslotsfunctionskeyswrite` | `Microsoft.Web/sites/functions/keys/write` and `Microsoft.Web/sites/slots/functions/keys/write` | Microsoft.Web/sites/functions/keys/write,Microsoft.Web/sites/slots/functions/keys/write | EXCLUDED | Invocation-only credential; impact depends on existing function behaviour. |
| `az-privilege-escalation/az-functions-app-privesc.md#microsoftwebsitesfunctionslistsecretsaction-and-microsoftwebsitesslotsfunctionslistsecretsaction` | `Microsoft.Web/sites/functions/listsecrets/action` and `Microsoft.Web/sites/slots/functions/listsecrets/action` | Microsoft.Web/sites/functions/listsecrets/action,Microsoft.Web/sites/slots/functions/listsecrets/action | EXCLUDED | Returns a trigger URL/function key; invocation only. |
| `az-privilege-escalation/az-functions-app-privesc.md#microsoftwebsiteshostfunctionkeyswrite-and-microsoftwebsitesslotshostfunctionkeyswrite` | `Microsoft.Web/sites/host/functionkeys/write` and `Microsoft.Web/sites/slots/host/functionkeys/write` | Microsoft.Web/sites/host/functionkeys/write,Microsoft.Web/sites/slots/host/functionkeys/write | EXCLUDED | Not a master key; authorizes invoking functions only. |
| `az-privilege-escalation/az-functions-app-privesc.md#microsoftwebsiteshostsystemkeyswrite-and-microsoftwebsitesslotshostsystemkeyswrite` | `Microsoft.Web/sites/host/systemkeys/write` and `Microsoft.Web/sites/slots/host/systemkeys/write` | Microsoft.Web/sites/host/systemkeys/write,Microsoft.Web/sites/slots/host/systemkeys/write | EXCLUDED | Authorizes extension webhooks only; invocation of existing code. |
| `az-privilege-escalation/az-functions-app-privesc.md#microsoftwebsitesconfiglistaction` | `Microsoft.Web/sites/config/list/action` | Microsoft.Web/sites/config/list/action | EXCLUDED | NEEDS SCHEMA: Config-list storage credentials alone do not prove the exact content-storage binding, overwrite of executable code, successful function execution, and usable named managed-identity token. |
| `az-privilege-escalation/az-functions-app-privesc.md#microsoftwebsitesslotsconfiglistaction` | `Microsoft.Web/sites/slots/config/list/action` | Microsoft.Web/sites/slots/config/list/action | EXCLUDED | Data exposure of settings/connection strings; content-dependent. |
| `az-privilege-escalation/az-functions-app-privesc.md#microsoftwebsitesconfiglistaction-microsoftwebsitesconfigwrite` | `Microsoft.Web/sites/config/list/action`, `Microsoft.Web/sites/config/write` | Microsoft.Web/sites/config/list/action,Microsoft.Web/sites/config/write | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-app-services-privesc.md#microsoftwebsitesconfigwrite` |
| `az-privilege-escalation/az-functions-app-privesc.md#microsoftwebsiteshostruntimevfswrite` | `Microsoft.Web/sites/hostruntime/vfs/write` | Microsoft.Web/sites/hostruntime/vfs/write | MAPPED | `azure-functions-hostruntime-vfs-write` |
| `az-privilege-escalation/az-functions-app-privesc.md#microsoftwebsitesslotspublishxmlaction` | `Microsoft.Web/sites/slots/publishxml/action` | Microsoft.Web/sites/slots/publishxml/action | MAPPED | `azure-appservice-slot-publishxml` |
| `az-privilege-escalation/az-functions-app-privesc.md#microsoftwebsitespublishxmlaction-microsoftwebsitesbasicpublishingcredentialspolicieswrite` | `Microsoft.Web/sites/publishxml/action`, `Microsoft.Web/sites/basicPublishingCredentialsPolicies/write` | Microsoft.Web/sites/basicPublishingCredentialsPolicies/write,Microsoft.Web/sites/publishxml/action | EXCLUDED | User-scope credentials only work on apps where the principal already has deployment authorization; no new gain. |
| `az-privilege-escalation/az-functions-app-privesc.md#microsoftwebsiteshostruntimevfsread` | `Microsoft.Web/sites/hostruntime/vfs/read` | Microsoft.Web/sites/hostruntime/vfs/read | EXCLUDED | Source code read only. |
| `az-privilege-escalation/az-functions-app-privesc.md#microsoftwebsitesfunctionstokenread` | `Microsoft.Web/sites/functions/token/read` | Microsoft.Web/sites/functions/token/read | EXCLUDED | NEEDS SCHEMA: A function admin token enables invocation, but no exact function behavior, managed-identity token disclosure, target identity, or newly allowed action is verified. |
| `az-privilege-escalation/az-functions-app-privesc.md#microsoftwebsitesconfigwrite` | `Microsoft.Web/sites/config/write` | Microsoft.Web/sites/config/write | EXCLUDED | Toggling functions alone is not an identity gain; config/write is modelled as azure-appservice-config-write. |
| `az-privilege-escalation/az-functions-app-privesc.md#rce-via-app-settings--environment-variables-microsoftwebsitesconfigwrite` | RCE via app-settings / environment variables (`Microsoft.Web/sites/config/write`) | Microsoft.Web/sites/config/write | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-app-services-privesc.md#microsoftwebsitesconfigwrite` |
| `az-privilege-escalation/az-functions-app-privesc.md#microsoftwebsitesconfigwrite-microsoftwebsitesconfiglistaction-microsoftwebsitesread-microsoftwebsitesconfiglistaction-microsoftwebsitesconfigread` | `Microsoft.Web/sites/config/write`, `Microsoft.Web/sites/config/list/action`, (`Microsoft.Web/sites/read`, `Microsoft.Web/sites/config/list/action`, `Microsoft.Web/sites/config/read`) | Microsoft.Web/sites/config/list/action,Microsoft.Web/sites/config/read,Microsoft.Web/sites/config/write,Microsoft.Web/sites/read | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-app-services-privesc.md#microsoftwebsitesconfigwrite` |
| `az-privilege-escalation/az-functions-app-privesc.md#microsoftwebsiteswrite-microsoftmanagedidentityuserassignedidentitiesassignaction-microsoftwebsitesread-microsoftwebsitesoperationresultsread` | `Microsoft.Web/sites/write`, `Microsoft.ManagedIdentity/userAssignedIdentities/assign/action` (`Microsoft.Web/sites/read`, `Microsoft.Web/sites/operationresults/read`) | Microsoft.ManagedIdentity/userAssignedIdentities/assign/action,Microsoft.Web/sites/operationresults/read,Microsoft.Web/sites/read,Microsoft.Web/sites/write | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-app-services-privesc.md#microsoftwebsiteswrite-microsoftwebsitesread-microsoftmanagedidentityuserassignedidentitiesassignaction` |
| `az-privilege-escalation/az-functions-app-privesc.md#remote-debugging` | Remote Debugging | Microsoft.Web/sites/config/write | MAPPED | `azure-functions-remote-debugging` |
| `az-privilege-escalation/az-functions-app-privesc.md#change-github-repo` | Change GitHub repo | Microsoft.Web/sites/write | MAPPED | `azure-functions-sites-write-source-control` |
| `az-privilege-escalation/az-functions-app-privesc.md#microsoftwebsiteshostruntime--arm-proxy-to-the-runtime-host-statusvfs-recon-key-routes-are-platform-blocked` | `Microsoft.Web/sites/hostruntime/*` — ARM-proxy to the runtime host (status/VFS recon; key routes are platform-blocked) | Microsoft.Web/sites/*,Microsoft.Web/sites/hostruntime/*,Microsoft.Web/sites/hostruntime/host/read | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-functions-app-privesc.md#microsoftwebsiteshostruntimevfswrite` |
| `az-privilege-escalation/az-functions-app-privesc.md#microsoftwebsitesconfigsnapshotslistsecretsaction--recover-rotatedremoved-secrets` | `Microsoft.Web/sites/config/snapshots/listsecrets/action` — recover rotated/removed secrets | Microsoft.Web/sites/*,Microsoft.Web/sites/config/snapshots/listsecrets/action | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-functions-app-privesc.md#microsoftwebsitesconfiglistaction` |
| `az-privilege-escalation/az-functions-app-privesc.md#microsoftwebsiteshybridconnectionnamespacesrelayslistkeysaction--on-premprivate-network-pivot` | `Microsoft.Web/sites/hybridconnectionnamespaces/relays/listkeys/action` — on-prem/private-network pivot | Microsoft.Web/sites/*,Microsoft.Web/sites/hybridconnectionnamespaces/relays/listkeys/action | EXCLUDED | On-prem / private network pivot; no identity. |
| `az-privilege-escalation/az-functions-app-privesc.md#microsoftwebsiteshostsyncaction--reload-tampered-keystriggers-enabler-low-alone` | `Microsoft.Web/sites/host/sync/action` — reload tampered keys/triggers (enabler, Low alone) | Microsoft.Web/sites/*,Microsoft.Web/sites/host/sync/action | EXCLUDED | Enabler only (reloads tampered keys/triggers); no gain alone. |
| `az-privilege-escalation/az-functions-app-privesc.md#references` | References |  | STRUCTURAL | references/enumeration |

## az-privilege-escalation/az-guest-configuration-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-guest-configuration-privesc.md#az---guest-configuration--machine-configuration-privesc` | Az - Guest Configuration / Machine Configuration Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-guest-configuration-privesc.md#guest-configuration` | Guest Configuration |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-guest-configuration-privesc.md#in-guest-rce-via-a-guest-configuration-assignment-marquee` |
| `az-privilege-escalation/az-guest-configuration-privesc.md#guest-configuration-overview` | Guest Configuration overview |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-guest-configuration-privesc.md#in-guest-rce-via-a-guest-configuration-assignment-marquee` |
| `az-privilege-escalation/az-guest-configuration-privesc.md#in-guest-rce-via-a-guest-configuration-assignment-marquee` | In-guest RCE via a guest configuration assignment (marquee) | Microsoft.Compute/virtualMachines/extensions/write,Microsoft.Compute/virtualMachines/write,Microsoft.GuestConfiguration/guestConfigurationAssignments/write | MAPPED | `azure-guestconfiguration-assignment-write-arc` |
| `az-privilege-escalation/az-guest-configuration-privesc.md#references` | References |  | STRUCTURAL | references/enumeration |

## az-privilege-escalation/az-hdinsight-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-hdinsight-privesc.md#az---hdinsight-privesc` | Az - HDInsight Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-hdinsight-privesc.md#hdinsight` | HDInsight |  | EXCLUDED | Introductory section. |
| `az-privilege-escalation/az-hdinsight-privesc.md#hdinsight-overview` | HDInsight overview |  | EXCLUDED | HDInsight node/credential identity outcome NEEDS SCHEMA for exact execution, usable token, and newly allowed action. |
| `az-privilege-escalation/az-hdinsight-privesc.md#dump-cluster-gateway-admin-credentials` | Dump cluster gateway admin credentials | Microsoft.HDInsight/clusters/getGatewaySettings/action | EXCLUDED | `azure-hdinsight-get-gateway-settings` NEEDS SCHEMA: exact bounded credential or workload execution to a named target and newly authorized action are unverified. |
| `az-privilege-escalation/az-hdinsight-privesc.md#reset-gateway-credentials-to-take-over-the-cluster` | Reset gateway credentials to take over the cluster | Microsoft.HDInsight/clusters/updateGatewaySettings/action | EXCLUDED | NEEDS SCHEMA: Gateway setting update does not prove a reachable endpoint, node-certificate disclosure, guest escalation, or named MI token/new action. |
| `az-privilege-escalation/az-hdinsight-privesc.md#arbitrary-root-rce-via-script-actions` | Arbitrary root RCE via Script Actions | Microsoft.HDInsight/clusters/executeScriptActions/action | EXCLUDED | NEEDS SCHEMA: Script-action permission alone does not prove execution on the exact node, usable node identity token, or newly allowed action. |
| `az-privilege-escalation/az-hdinsight-privesc.md#escalate-from-node-rce-to-storage--managed-identity` | Escalate from node RCE to storage & managed identity |  | EXCLUDED | Post-RCE step, not an independent permission combination; the cluster user-assigned identity it reaches is the target of the HDInsight code-execution entries (azure-hdinsight-execute-script-actions and siblings). Storage account keys in cluster configuration are data-plane credentials. |
| `az-privilege-escalation/az-hdinsight-privesc.md#seed-root-code--attach-an-identity-via-cluster-create-or-update` | Seed root code / attach an identity via cluster create-or-update | Microsoft.HDInsight/clusters/write | EXCLUDED | NEEDS SCHEMA: Creating a cluster with an assignable UAMI does not prove source access to a node/session, identity token, or newly allowed action. |
| `az-privilege-escalation/az-hdinsight-privesc.md#root-rce--persistence-via-hdinsight-applications` | Root RCE + persistence via HDInsight Applications | Microsoft.HDInsight/clusters/applications/write | EXCLUDED | NEEDS SCHEMA: Application write does not prove accepted deployment, execution on the identity-bearing node, or token/new action. |
| `az-privilege-escalation/az-hdinsight-privesc.md#references` | References |  | STRUCTURAL | section/how-to heading; no technique |

## az-privilege-escalation/az-image-builder-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-image-builder-privesc.md#az---vm-image-builder-privesc` | Az - VM Image Builder Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-image-builder-privesc.md#azure-vm-image-builder` | Azure VM Image Builder |  | EXCLUDED | Introductory section. |
| `az-privilege-escalation/az-image-builder-privesc.md#image-builder-overview` | Image Builder overview |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-image-builder-privesc.md#hijack-an-existing-image-template` |
| `az-privilege-escalation/az-image-builder-privesc.md#customizer-rce--build-identity-token-theft-marquee` | Customizer RCE + build-identity token theft (marquee) | Microsoft.VirtualMachineImages/imageTemplates/write | MAPPED | `azure-imagebuilder-template-create-via-template-identity` |
| `az-privilege-escalation/az-image-builder-privesc.md#hijack-an-existing-image-template` | Hijack an existing image template |  | EXCLUDED | `azure-imagebuilder-template-hijack-existing` NEEDS SCHEMA: exact bounded credential or workload execution to a named target and newly authorized action are unverified. |
| `az-privilege-escalation/az-image-builder-privesc.md#staging-rg--build-vm-lateral-movement` | Staging RG / build-VM lateral movement | Microsoft.Network/virtualNetworks/read,Microsoft.Network/virtualNetworks/subnets/join/action | EXCLUDED | Network pivot and staging-artifact tampering without a new identity for the source; the build-VM identity requires exact template and execution proof before a path is emitted. |
| `az-privilege-escalation/az-image-builder-privesc.md#pivot-to-raw-compute` | Pivot to raw Compute |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputevirtualmachinesextensionswrite`, `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputevirtualmachinesruncommandaction` |
| `az-privilege-escalation/az-image-builder-privesc.md#references` | References |  | STRUCTURAL | references/enumeration |

## az-privilege-escalation/az-intune-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-intune-privesc.md#az---intune-privesc` | Az - Intune Privesc |  | STRUCTURAL | title/reference/intro heading |
| `az-privilege-escalation/az-intune-privesc.md#intune` | Intune |  | EXCLUDED | Section header; the concrete techniques are the sub-headings listed below. |
| `az-privilege-escalation/az-intune-privesc.md#cloud---on-prem` | Cloud -> On-Prem |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-intune-privesc.md#fleet-rce-via-platform-scripts-system-over-graph` |
| `az-privilege-escalation/az-intune-privesc.md#fleet-rce-via-platform-scripts-system-over-graph` | Fleet RCE via platform scripts (SYSTEM) over Graph |  | EXCLUDED | `azure-intune-managed-device-user-code-execution` NEEDS SCHEMA: exact device delivery, user session, and captured usable user credential are unverified. |
| `az-privilege-escalation/az-intune-privesc.md#macos-shell-scripts-as-root--win32-apps-as-system` | macOS shell scripts as root / Win32 apps as SYSTEM |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-intune-privesc.md#fleet-rce-via-platform-scripts-system-over-graph` |
| `az-privilege-escalation/az-intune-privesc.md#conditional-access-bypass-via-compliance-tampering--company-portal-foci` | Conditional Access bypass via compliance tampering / Company Portal FOCI |  | EXCLUDED | Conditional Access / device-compliance bypass for an identity the attacker already controls; no new principal is gained. |
| `az-privilege-escalation/az-intune-privesc.md#privesc-chain--intune-administrator--intune-scoped-sp---global-admin` | Privesc chain — Intune Administrator / Intune-scoped SP -> Global Admin |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-intune-privesc.md#fleet-rce-via-platform-scripts-system-over-graph` |
| `az-privilege-escalation/az-intune-privesc.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-privilege-escalation/az-iot-hub-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-iot-hub-privesc.md#az---iot-hub-privesc` | Az - IoT Hub Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-iot-hub-privesc.md#iot-hub` | IoT Hub |  | EXCLUDED | Introductory section. |
| `az-privilege-escalation/az-iot-hub-privesc.md#iot-hub-shared-access-policy-keys` | IoT Hub shared-access policy keys |  | EXCLUDED | NEEDS SCHEMA: Exact IoT Hub policy identity, usable key, and newly permitted hub action must be verified. |
| `az-privilege-escalation/az-iot-hub-privesc.md#device-provisioning-service-shared-access-policy-keys` | Device Provisioning Service shared-access policy keys |  | EXCLUDED | NEEDS SCHEMA: Exact DPS policy identity, usable key, and newly permitted provisioning action must be verified. |
| `az-privilege-escalation/az-iot-hub-privesc.md#device-and-module-identity-takeover` | Device and module identity takeover |  | EXCLUDED | NEEDS SCHEMA: Exact device or module identity, usable credential or assigned key, and newly permitted device action must be verified. |
| `az-privilege-escalation/az-iot-hub-privesc.md#device-twin-disclosure-and-commandconfiguration-injection` | Device twin disclosure and command/configuration injection |  | STRUCTURAL | pointer to post-exploitation page |
| `az-privilege-escalation/az-iot-hub-privesc.md#cloud-to-device-messages-direct-methods-and-jobs` | Cloud-to-device messages, direct methods, and jobs |  | STRUCTURAL | pointer to post-exploitation page |
| `az-privilege-escalation/az-iot-hub-privesc.md#full-registry-export-and-import` | Full registry export and import |  | EXCLUDED | NEEDS SCHEMA: Exact exported device identity, usable credential, and newly permitted device action must be verified. |
| `az-privilege-escalation/az-iot-hub-privesc.md#dps-attestation-key-disclosure-and-unauthorized-provisioning` | DPS attestation-key disclosure and unauthorized provisioning |  | EXCLUDED | NEEDS SCHEMA: Exact attested device or enrollment identity and newly permitted provisioning action must be verified. |
| `az-privilege-escalation/az-iot-hub-privesc.md#lower-impact-boundaries` | Lower-impact boundaries |  | EXCLUDED | Low impact per page. |
| `az-privilege-escalation/az-iot-hub-privesc.md#hub-property-abuse-with-microsoftdevicesiothubswrite` | Hub-property abuse with `Microsoft.Devices/iotHubs/Write` | Microsoft.Devices/iotHubs/Write | EXCLUDED | Persistence, telemetry exfiltration and data-plane credentials over IoT device identities, which are not Azure/Entra principals. An identity attached to the hub is only used by the service for routing/egress; no code runs as it, so its token is never obtained by the source (confused-deputy egress only). |
| `az-privilege-escalation/az-iot-hub-privesc.md#covert-built-in-events-consumer-group-with-eventhubendpointsconsumergroupswrite` | Covert built-in-events consumer group with `eventHubEndpoints/consumerGroups/Write` |  | STRUCTURAL | pointer to post-exploitation page |
| `az-privilege-escalation/az-iot-hub-privesc.md#rogue-x509-ca-for-device-auth-with-iothubscertificateswrite-and-the-dps-equivalent` | Rogue X.509 CA for device auth with `iotHubs/certificates/Write` (and the DPS equivalent) |  | EXCLUDED | NEEDS SCHEMA: Exact device identity trusted under the CA and newly permitted authentication action must be verified. |

## az-privilege-escalation/az-key-vault-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-key-vault-privesc.md#az---key-vault-privesc` | Az - Key Vault Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-key-vault-privesc.md#key-vault` | Key Vault |  | EXCLUDED | Introductory section. |
| `az-privilege-escalation/az-key-vault-privesc.md#azure-key-vault` | Azure Key Vault |  | STRUCTURAL | section grouping heading |
| `az-privilege-escalation/az-key-vault-privesc.md#microsoftkeyvaultvaultsaccesspolicieswrite-microsoftkeyvaultvaultsread` | `Microsoft.KeyVault/vaults/accessPolicies/write` (`Microsoft.KeyVault/vaults/read`) | Microsoft.KeyVault/vaults/accessPolicies/write;Microsoft.KeyVault/vaults/write;Microsoft.KeyVault/vaults/secrets/getSecret/action | EXCLUDED | Strict principal-boundary audit: The credential_stored_in_scope selector has no exact usable credential and identified target-principal evidence enforcement for this technique; a secret read or arbitrary configuration change alone is not an established principal escalation. |
| `az-privilege-escalation/az-key-vault-privesc.md#microsoftkeyvaultvaultsdeployaction--microsoftresourcesdeploymentswrite` | `Microsoft.KeyVault/vaults/deploy/action` + `Microsoft.Resources/deployments/write` | Microsoft.KeyVault/vaults/deploy/action;Microsoft.Resources/deployments/write | EXCLUDED | Strict principal-boundary audit: The credential_stored_in_scope selector has no exact usable credential and identified target-principal evidence enforcement for this technique; a secret read or arbitrary configuration change alone is not an established principal escalation. |
| `az-privilege-escalation/az-key-vault-privesc.md#write-only-secret-poisoning` | Write-only secret poisoning |  | EXCLUDED | `azure-keyvault-secret-poisoning-consumer` NEEDS SCHEMA: exact written object or message, consumer binding and trigger, observed execution, and a newly obtained identity token or action are unverified. |
| `az-privilege-escalation/az-key-vault-privesc.md#modify-network-restrictions` | Modify Network Restrictions |  | EXCLUDED | Network reachability only. |
| `az-privilege-escalation/az-key-vault-privesc.md#forge-signatures-with-microsoftkeyvaultvaultskeyssignaction` | Forge signatures with `Microsoft.KeyVault/vaults/keys/sign/action` | Microsoft.KeyVault/vaults/keys/sign/action | EXCLUDED | Strict principal-boundary audit: The credential_stored_in_scope selector has no exact usable credential and identified target-principal evidence enforcement for this technique; a secret read or arbitrary configuration change alone is not an established principal escalation. |
| `az-privilege-escalation/az-key-vault-privesc.md#enable-the-deployment-path-with-microsoftkeyvaultvaultswrite` | Enable the deployment path with `Microsoft.KeyVault/vaults/write` | Microsoft.KeyVault/vaults/write | EXCLUDED | Enabler of the template-deployment path; vaults/write is already a requirement branch of azure-keyvault-secret-read-sp-credentials (it can rewrite accessPolicies directly), and enabledForTemplateDeployment is the condition of azure-keyvault-template-deployment-secret-reference. |
| `az-privilege-escalation/az-key-vault-privesc.md#swap-the-authorization-model-with-microsoftkeyvaultvaultswrite-enablerbacauthorization-toggle` | Swap the authorization model with `Microsoft.KeyVault/vaults/write` (`enableRbacAuthorization` toggle) | Microsoft.KeyVault/vaults/write | EXCLUDED | Same permission and target set as the vaults/write branch of azure-keyvault-secret-read-sp-credentials (switching to the access-policy model and rewriting accessPolicies); the toggle-to-RBAC direction is denial of service. |
| `az-privilege-escalation/az-key-vault-privesc.md#approve-an-attacker-private-endpoint-to-reach-a-publicnetworkaccessdisabled-vault` | Approve an attacker private endpoint to reach a `publicNetworkAccess=Disabled` vault |  | EXCLUDED | Network reachability only; condition network_reachable of the Key Vault entries. |
| `az-privilege-escalation/az-key-vault-privesc.md#references` | References |  | STRUCTURAL | references |

## az-privilege-escalation/az-kubernetes-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-kubernetes-privesc.md#az---kubernetes-privesc` | Az - Kubernetes Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-kubernetes-privesc.md#azure-kubernetes-service` | Azure Kubernetes Service |  | EXCLUDED | Introductory section. |
| `az-privilege-escalation/az-kubernetes-privesc.md#aks-cluster-credentials` | AKS cluster credentials | Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action,Microsoft.HybridContainerService/provisionedClusters/,Microsoft.Kubernetes/connectedClusters/ | MAPPED | `azure-aks-list-cluster-admin-credential` `azure-aks-list-cluster-user-credential` `azure-hybrid-k8s-list-cluster-admin-credential` |
| `az-privilege-escalation/az-kubernetes-privesc.md#alternative-cluster-credential-retrieval-apis` | Alternative cluster-credential retrieval APIs | Microsoft.ContainerService/fleets/listCredentials/action,Microsoft.ContainerService/managedClusters/accessProfiles/listCredential/action,Microsoft.ContainerService/managedClusters/listClusterMonitoringUserCredential/action,Microsoft.ContainerService/managedClusters/managedNamespaces/listCredential/action | MAPPED | `azure-aks-access-profile-list-credential` |
| `az-privilege-escalation/az-kubernetes-privesc.md#run-command--in-cluster-execution-with-no-kubeconfig-and-no-network-line-of-sight` | Run Command — in-cluster execution with no kubeconfig and no network line-of-sight | Microsoft.ContainerService/managedClusters/commandResults/read,Microsoft.ContainerService/managedClusters/runCommand/action | MAPPED | `azure-aks-run-command` |
| `az-privilege-escalation/az-kubernetes-privesc.md#re-arm-the-built-in-cluster-admin--graft-an-attacker-entra-admin-group-managedclusterswrite` | Re-arm the built-in cluster admin / graft an attacker Entra admin group (`managedClusters/write`) | Microsoft.ContainerService/managedClusters/write | MAPPED | `azure-aks-managedclusters-write-enable-local-accounts` covers the local-account variant; the Entra admin-group variant is excluded until membership, Entra integration, kubeconfig, and reachability are verified. |
| `az-privilege-escalation/az-kubernetes-privesc.md#vm-scale-set-run-command-on-aks-workers` | VM scale set Run Command on AKS workers | Microsoft.Compute/virtualMachineScaleSets/virtualMachines/runCommand/action | MAPPED | `azure-aks-vmss-node-run-command` |
| `az-privilege-escalation/az-kubernetes-privesc.md#external-oidc-authentication-on-aks` | External OIDC authentication on AKS |  | EXCLUDED | Preview feature; becomes a pivot only when the mapped aks:jwt identity holds Kubernetes RBAC, and neither the authenticator configuration nor its write permission is collected. Not modelled until JWT authenticator facts exist. |
| `az-privilege-escalation/az-kubernetes-privesc.md#kubernetes-rbac-operations` | Kubernetes RBAC operations | ClusterRoleBinding write plus bind cluster-admin; groups impersonate system:masters | MAPPED | `azure-aks-azure-rbac-k8s-rbac-write` `azure-aks-azure-rbac-impersonate`; excluded pending exact subject/permission join: "AKS namespace RoleBinding self-grant and bound ClusterRole escalation variants", "AKS user or ServiceAccount impersonation without a proven admin-bound subject", "Namespace-scoped AKS RBAC Writer creates a Pod as a more privileged ServiceAccount". Generic Secret reads are linked to post exploitation. |
| `az-privilege-escalation/az-kubernetes-privesc.md#azure-red-hat-openshift-aro-cluster-credentials` | Azure Red Hat OpenShift (ARO) cluster credentials | Microsoft.RedHatOpenShift/openShiftClusters/listCredentials/action | MAPPED | `azure-aro-list-credentials` |

## az-privilege-escalation/az-load-testing-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-load-testing-privesc.md#az---load-testing-privesc` | Az - Load Testing Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-load-testing-privesc.md#azure-load-testing` | Azure Load Testing |  | EXCLUDED | Introductory section. |
| `az-privilege-escalation/az-load-testing-privesc.md#load-testing-overview` | Load Testing overview |  | EXCLUDED | Background section; modelled by azure-loadtesting-test-engine-identity. |
| `az-privilege-escalation/az-load-testing-privesc.md#test-engine-rce--managed-identity-token-theft-marquee` | Test-engine RCE + managed-identity token theft (marquee) | Microsoft.LoadTestService/loadtests/*,Microsoft.LoadTestService/loadtests/write,Microsoft.ManagedIdentity/userAssignedIdentities/*/assign/action | MAPPED | `azure-loadtesting-test-engine-identity` `azure-loadtesting-assign-user-assigned-identity` |
| `az-privilege-escalation/az-load-testing-privesc.md#key-vault-secret--certificate-reference-abuse` | Key Vault secret / certificate reference abuse | Microsoft.LoadTestService/loadtests/* | EXCLUDED | Partial gain (Key Vault secret reads of the KeyVault reference identity) using the same data actions as azure-loadtesting-test-engine-identity, which already reaches every identity attached to the load test resource. |
| `az-privilege-escalation/az-load-testing-privesc.md#references` | References |  | STRUCTURAL | section/how-to heading; no technique |

## az-privilege-escalation/az-log-analytics-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-log-analytics-privesc.md#az---log-analytics-privesc` | Az - Log Analytics Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-log-analytics-privesc.md#log-analytics` | Log Analytics |  | EXCLUDED | Introductory section; shared keys only allow log ingestion/poisoning and disruption, no identity gain. |
| `az-privilege-escalation/az-log-analytics-privesc.md#attach-an-automation-account-via-workspaceslinkedserviceswrite` | Attach an Automation account via `workspaces/linkedServices/write` |  | EXCLUDED | Code execution depends on legacy agent-based Update Management / Change Tracking onboarding (retired with the Log Analytics agent) and on an Automation account the source already controls; no new identity from the link itself. |

## az-privilege-escalation/az-logic-apps-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-logic-apps-privesc.md#az---logic-apps-privesc` | Az - Logic Apps Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-logic-apps-privesc.md#logic-apps` | Logic Apps |  | EXCLUDED | Introductory section. |
| `az-privilege-escalation/az-logic-apps-privesc.md#logic-apps-privesc` | Logic Apps Privesc |  | STRUCTURAL | section grouping heading; techniques are its subsections |
| `az-privilege-escalation/az-logic-apps-privesc.md#microsoftresourcessubscriptionsresourcegroupsread-microsoftlogicworkflowsread-microsoftlogicworkflowswrite--microsoftmanagedidentityuserassignedidentitiesassignaction--microsoftlogicworkflowstriggersrunaction` | (`Microsoft.Resources/subscriptions/resourcegroups/read`, `Microsoft.Logic/workflows/read`, `Microsoft.Logic/workflows/write` && `Microsoft.ManagedIdentity/userAssignedIdentities/assign/action`) && (`Microsoft.Logic/workflows/triggers/run/action`) | Microsoft.Logic/workflows/read,Microsoft.Logic/workflows/triggers/run/action,Microsoft.Logic/workflows/write,Microsoft.ManagedIdentity/userAssignedIdentities/assign/action,Microsoft.Resources/subscriptions/resourcegroups/read | MAPPED | `azure-logicapp-assign-user-assigned-identity` |
| `az-privilege-escalation/az-logic-apps-privesc.md#microsoftlogicworkflowswrite` | Microsoft.Logic/workflows/write | Microsoft.Logic/workflows/write | MAPPED | `azure-logicapp-workflow-write-existing-identity` |
| `az-privilege-escalation/az-logic-apps-privesc.md#microsoftlogicworkflowstriggerslistcallbackurlaction` | `Microsoft.Logic/workflows/triggers/listCallbackUrl/action` | Microsoft.Logic/workflows/triggers/listCallbackUrl/action | EXCLUDED | Runs existing workflow logic only. |
| `az-privilege-escalation/az-logic-apps-privesc.md#microsoftlogicworkflowslistcallbackurlaction` | `Microsoft.Logic/workflows/listCallbackUrl/action` | Microsoft.Logic/workflows/listCallbackUrl/action | EXCLUDED | Runs existing workflow logic only. |
| `az-privilege-escalation/az-logic-apps-privesc.md#integration-account-signed-callback-permissions` | Integration Account signed callback permissions | Microsoft.Logic/integrationAccounts/.../listCallbackUrl/action | EXCLUDED | Artifact content read. |
| `az-privilege-escalation/az-logic-apps-privesc.md#microsoftlogicintegrationaccountsagreementslistsecretsaction--steal-b2bedi-authentication-secrets` | `Microsoft.Logic/integrationAccounts/agreements/listSecrets/action` — steal B2B/EDI authentication secrets | Microsoft.Logic/integrationAccounts/agreements/listSecrets/action | EXCLUDED | B2B/EDI partner secrets; data read, no Azure/Entra identity. |
| `az-privilege-escalation/az-logic-apps-privesc.md#microsoftlogicintegrationaccountsregenerateaccesskeyaction--rotate-the-artifact-signing-key-dos--fresh-signing-secret` | `Microsoft.Logic/integrationAccounts/regenerateAccessKey/action` — rotate the artifact-signing key (DoS + fresh signing secret) | Microsoft.Logic/integrationAccounts/regenerateAccessKey/action | EXCLUDED | Denial of service and signing material for artifact callback URLs; no new identity. |
| `az-privilege-escalation/az-logic-apps-privesc.md#microsoftlogicworkflowsversionstriggerslistcallbackurlaction` | `Microsoft.Logic/workflows/versions/triggers/listCallbackUrl/action` | Microsoft.Logic/workflows/versions/triggers/listCallbackUrl/action | EXCLUDED | Runs stored workflow logic only. |
| `az-privilege-escalation/az-logic-apps-privesc.md#microsoftlogicworkflowstriggersrunaction` | `Microsoft.Logic/workflows/triggers/run/action` | Microsoft.Logic/workflows/triggers/run/action | EXCLUDED | Runs existing workflow logic only. |
| `az-privilege-escalation/az-logic-apps-privesc.md#microsoftlogicworkflowsrunaction` | `Microsoft.Logic/workflows/run/action` | Microsoft.Logic/workflows/run/action | EXCLUDED | Runs existing workflow logic only. |
| `az-privilege-escalation/az-logic-apps-privesc.md#microsoftlogicworkflowstriggershistoriesresubmitaction` | `Microsoft.Logic/workflows/triggers/histories/resubmit/action` | Microsoft.Logic/workflows/triggers/histories/resubmit/action | EXCLUDED | Replays existing logic only. |
| `az-privilege-escalation/az-logic-apps-privesc.md#microsoftlogicworkflowsrunsactionsread` | `Microsoft.Logic/workflows/runs/actions/read` | Microsoft.Logic/workflows/runs/actions/read | EXCLUDED | Data read. |
| `az-privilege-escalation/az-logic-apps-privesc.md#microsoftlogicworkflowsrunsactionsrequesthistoriesread` | `Microsoft.Logic/workflows/runs/actions/requestHistories/read` | Microsoft.Logic/workflows/runs/actions/requestHistories/read | EXCLUDED | Data read. |
| `az-privilege-escalation/az-logic-apps-privesc.md#microsoftlogicworkflowsaccesskeyslistaction` | `Microsoft.Logic/workflows/accessKeys/list/action` | Microsoft.Logic/workflows/accessKeys/list/action | EXCLUDED | Callback signing material; existing logic only. |
| `az-privilege-escalation/az-logic-apps-privesc.md#microsoftlogicworkflowsread-microsoftlogicworkflowswrite--microsoftmanagedidentityuserassignedidentitiesassignaction` | `Microsoft.Logic/workflows/read`, `Microsoft.Logic/workflows/write` && `Microsoft.ManagedIdentity/userAssignedIdentities/assign/action` | Microsoft.Logic/workflows/read,Microsoft.Logic/workflows/write,Microsoft.ManagedIdentity/userAssignedIdentities/assign/action | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-logic-apps-privesc.md#microsoftresourcessubscriptionsresourcegroupsread-microsoftlogicworkflowsread-microsoftlogicworkflowswrite--microsoftmanagedidentityuserassignedidentitiesassignaction--microsoftlogicworkflowstriggersrunaction` |
| `az-privilege-escalation/az-logic-apps-privesc.md#microsoftwebsitespublishaction-microsoftwebsitesread-microsoftwebsitesbasicpublishingcredentialspoliciesread-microsoftwebsitesconfiglistaction-microsoftwebsitesstartaction` | `Microsoft.Web/sites/publish/action`, `Microsoft.Web/sites/read`, `Microsoft.Web/sites/basicPublishingCredentialsPolicies/read`, `Microsoft.Web/sites/config/list/action` (`Microsoft.Web/sites/start/action`) | Microsoft.Web/sites/basicPublishingCredentialsPolicies/read,Microsoft.Web/sites/config/list/action,Microsoft.Web/sites/publish/action,Microsoft.Web/sites/read,Microsoft.Web/sites/start/action | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-app-services-privesc.md#microsoftwebsitespublishaction-and-microsoftwebsitesslotspublishaction`, `az-privilege-escalation/az-app-services-privesc.md#publish-code-using-scm-credentials` |
| `az-privilege-escalation/az-logic-apps-privesc.md#microsoftwebsiteshostlistkeysaction-microsoftwebsiteshostruntime---standard-logic-app-host-key-theft--anonymous-workflow-invoke` | `Microsoft.Web/sites/host/listkeys/action`, `Microsoft.Web/sites/hostruntime/*` - Standard Logic App host-key theft & anonymous workflow invoke | Microsoft.Web/sites/host/listkeys/action,Microsoft.Web/sites/hostruntime/*,Microsoft.Web/sites/hostruntime/host/_master/read,Microsoft.Web/sites/hostruntime/webhooks/api/workflows/triggers/listCallbackUrl/action,Microsoft.Web/sites/read | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-functions-app-privesc.md#microsoftwebsiteshostlistkeysaction-and-microsoftwebsitesslotshostlistkeysaction` |
| `az-privilege-escalation/az-logic-apps-privesc.md#microsoftwebsitesconfigwrite---rce-via-app-settings--environment-variables-standard-logic-apps` | `Microsoft.Web/sites/config/write` - RCE via app settings / environment variables (Standard Logic Apps) | Microsoft.Web/sites/config/write | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-app-services-privesc.md#microsoftwebsitesconfigwrite` |
| `az-privilege-escalation/az-logic-apps-privesc.md#privilege-escalation-and-post-exploitation` | Privilege Escalation and Post-Exploitation |  | STRUCTURAL | section grouping heading; techniques are its subsections |
| `az-privilege-escalation/az-logic-apps-privesc.md#microsoftwebconnectionswrite---redirect-a-future-workflow-through-attacker-credentials` | `Microsoft.Web/connections/write` - Redirect a future workflow through attacker credentials | Microsoft.Web/connections/write | EXCLUDED | Data redirection; no identity gain. |
| `az-privilege-escalation/az-logic-apps-privesc.md#microsoftwebconnectionsaccesspolicieswrite---grant-a-workflow-use-of-unreadable-connection-credentials` | `Microsoft.Web/connections/accessPolicies/Write` - Grant a workflow use of unreadable connection credentials | Microsoft.Web/connections/accessPolicies/Write,Microsoft.Web/connections/accessPolicies/write | EXCLUDED | Strict principal-boundary audit: The credential_stored_in_scope selector has no exact usable credential and identified target-principal evidence enforcement for this technique; a secret read or arbitrary configuration change alone is not an established principal escalation. |
| `az-privilege-escalation/az-logic-apps-privesc.md#microsoftwebconnectionslistconnectionkeysaction---steal-an-api-connections-runtime-credential` | `Microsoft.Web/connections/listConnectionKeys/action` - Steal an API connection's runtime credential | Microsoft.Web/connections/confirmConsentCode/action,Microsoft.Web/connections/listConnectionKeys/action,Microsoft.Web/connections/listConsentLinks/action | EXCLUDED | Strict principal-boundary audit: The credential_stored_in_scope selector has no exact usable credential and identified target-principal evidence enforcement for this technique; a secret read or arbitrary configuration change alone is not an established principal escalation. |
| `az-privilege-escalation/az-logic-apps-privesc.md#microsoftlogicintegrationaccountsmapswrite---poison-a-future-xslt-transformation` | `Microsoft.Logic/integrationAccounts/maps/write` - Poison a future XSLT transformation | Microsoft.Logic/integrationAccounts/maps/write | EXCLUDED | Data manipulation; consumer-dependent. |
| `az-privilege-escalation/az-logic-apps-privesc.md#references` | References |  | STRUCTURAL | references/enumeration |

## az-privilege-escalation/az-machine-learning-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-machine-learning-privesc.md#az---machine-learning-privesc` | Az - Machine Learning Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-machine-learning-privesc.md#azure-machine-learning` | Azure Machine Learning |  | EXCLUDED | Introductory section; techniques are mapped by their own headings. |
| `az-privilege-escalation/az-machine-learning-privesc.md#azure-ml-overview` | Azure ML overview |  | EXCLUDED | Overview only; the compute, datastore and endpoint techniques are mapped individually. |
| `az-privilege-escalation/az-machine-learning-privesc.md#compute-as-identity-rce-marquee-privesc` | Compute-as-identity RCE (marquee privesc) | Microsoft.MachineLearningServices/workspaces/computes/write,Microsoft.ManagedIdentity/userAssignedIdentities/assign/action | EXCLUDED | `azure-ml-compute-code-execution-marquee` NEEDS SCHEMA: exact bounded credential or workload execution to a named target and newly authorized action are unverified. |
| `az-privilege-escalation/az-machine-learning-privesc.md#datastore-secret-theft` | Datastore secret theft | Microsoft.MachineLearningServices/workspaces/datastores/listsecrets/action | EXCLUDED | Covered by azure-ml-connection-secrets, which includes datastores/listSecrets/action and connections/listsecrets/action and targets service principals whose credentials are stored in the workspace; account-key/SAS datastores are data access only. |
| `az-privilege-escalation/az-machine-learning-privesc.md#dump-workspace-linked-resource-keys` | Dump workspace linked-resource keys | Microsoft.MachineLearningServices/workspaces/listKeys/action | EXCLUDED | `azure-ml-workspace-linked-keys-workload-poisoning` NEEDS SCHEMA: exact bounded credential or workload execution to a named target and newly authorized action are unverified. |
| `az-privilege-escalation/az-machine-learning-privesc.md#attached-compute-credential-theft-with-computeslistkeysaction` | Attached-compute credential theft with `computes/listKeys/action` | Microsoft.MachineLearningServices/workspaces/computes/listKeys/action | EXCLUDED | Returned credential depends on what external compute (AKS/VM/HDInsight/Databricks) was attached and with which credential; the reachable principal cannot be resolved from RBAC and inventory. |
| `az-privilege-escalation/az-machine-learning-privesc.md#notebook-credential-theft-with-read-only-verbs-listnotebookkeys--listnotebookaccesstoken` | Notebook credential theft with `read`-only verbs (`listNotebookKeys` / `listNotebookAccessToken`) | Microsoft.MachineLearningServices/workspaces/*/read,Microsoft.MachineLearningServices/workspaces/listNotebookKeys/read | EXCLUDED | Notebook file-store access (data); secrets embedded in notebooks are content-dependent and not an identity edge. |
| `az-privilege-escalation/az-machine-learning-privesc.md#online--batch--serverless-endpoint-key-theft--malicious-deployment` | Online / batch / serverless endpoint key theft & malicious deployment |  | EXCLUDED | Scoring keys/tokens only invoke the model (no identity). Malicious deployment as the endpoint identity is modelled by azure-ml-online-deployment-existing-endpoint and azure-ml-online-endpoint-create-with-user-assigned-identity. |
| `az-privilege-escalation/az-machine-learning-privesc.md#workspace-createmodify-as-an-identity-staging-primitive` | Workspace create/modify as an identity-staging primitive | Microsoft.MachineLearningServices/workspaces/write,Microsoft.ManagedIdentity/userAssignedIdentities/assign/action | EXCLUDED | NEEDS SCHEMA: Workspace UAMI attachment does not prove serverless availability, exact job-to-primary-UAMI selection, successful run, and usable target token/new action. |
| `az-privilege-escalation/az-machine-learning-privesc.md#references` | References |  | STRUCTURAL | section/how-to heading; no technique |

## az-privilege-escalation/az-managed-applications-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-managed-applications-privesc.md#az---managed-applications-privesc` | Az - Managed Applications Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-managed-applications-privesc.md#managed-applications` | Managed Applications |  | EXCLUDED | Introductory section. |
| `az-privilege-escalation/az-managed-applications-privesc.md#managed-applications-overview` | Managed Applications overview |  | EXCLUDED | Overview of publisher authorizations and deny assignments; the escalation is mapped under listTokens. |
| `az-privilege-escalation/az-managed-applications-privesc.md#listtokens--cross-tenant-managed-identity-token-export-marquee` | `listTokens` — cross-tenant managed-identity token export (marquee) | Microsoft.Solutions/applications/listTokens/action | MAPPED | `azure-managedapp-list-tokens` |
| `az-privilege-escalation/az-managed-applications-privesc.md#deploy-as-identity-inside-a-managed-app` | Deploy-as-identity inside a managed app |  | EXCLUDED | The deployment only acts inside a newly created managed resource group, with authorizations the attacker defines for itself; it does not reach pre-existing identities. Cross-tenant delegatedManagedIdentityResourceId grants need publisher-tenant setup. Persistence, not escalation. |
| `az-privilege-escalation/az-managed-applications-privesc.md#references` | References |  | STRUCTURAL | references |

## az-privilege-escalation/az-managed-devops-pools-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-managed-devops-pools-privesc.md#az---managed-devops-pools-privesc` | Az - Managed DevOps Pools Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-managed-devops-pools-privesc.md#managed-devops-pools` | Managed DevOps Pools |  | EXCLUDED | Introductory section. |
| `az-privilege-escalation/az-managed-devops-pools-privesc.md#bind-a-privileged-identity-to-a-pool-poolswrite--rce-as-identity-via-cicd-jobs` | Bind a privileged identity to a pool (`pools/write`) → RCE-as-identity via CI/CD jobs | Microsoft.DevOpsInfrastructure/pools/write,Microsoft.ManagedIdentity/userAssignedIdentities/assign/action | EXCLUDED | NEEDS SCHEMA: Pool write does not prove an accepted attacker-controlled job executed on the existing pool or reached its named identity. |
| `az-privilege-escalation/az-managed-devops-pools-privesc.md#references` | References |  | STRUCTURAL | references/enumeration |

## az-privilege-escalation/az-managed-grafana-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-managed-grafana-privesc.md#az---azure-managed-grafana-privesc` | Az - Azure Managed Grafana Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-managed-grafana-privesc.md#azure-managed-grafana` | Azure Managed Grafana |  | EXCLUDED | Introductory section. |
| `az-privilege-escalation/az-managed-grafana-privesc.md#microsoftdashboardgrafanaactasgrafanaadminaction` | `Microsoft.Dashboard/grafana/ActAsGrafanaAdmin/action` | Microsoft.Dashboard/grafana/ActAsGrafanaAdmin/action | MAPPED | `azure-grafana-act-as-admin` |
| `az-privilege-escalation/az-managed-grafana-privesc.md#enumerate-without-arm-read` | Enumerate without ARM read |  | SUBSECTION | of #microsoftdashboardgrafanaactasgrafanaadminaction: MAPPED azure-grafana-act-as-admin |
| `az-privilege-escalation/az-managed-grafana-privesc.md#mint-a-persistent-grafana-admin-token` | Mint a persistent Grafana Admin token |  | SUBSECTION | of #microsoftdashboardgrafanaactasgrafanaadminaction: MAPPED azure-grafana-act-as-admin |
| `az-privilege-escalation/az-managed-grafana-privesc.md#permission-boundary` | Permission boundary |  | SUBSECTION | of #microsoftdashboardgrafanaactasgrafanaadminaction: MAPPED azure-grafana-act-as-admin |
| `az-privilege-escalation/az-managed-grafana-privesc.md#microsoftdashboardgrafanawrite--mi-attach--remove-the-service-account-persistence-boundary` | `Microsoft.Dashboard/grafana/write` — MI attach + remove the service-account persistence boundary | Microsoft.Dashboard/grafana/write | EXCLUDED | `azure-grafana-assign-user-assigned-identity` NEEDS SCHEMA: exact execution or token retrieval for a named identity and a newly authorized action are unverified. |
| `az-privilege-escalation/az-managed-grafana-privesc.md#microsoftdashboardgrafanaactasgrafanaeditoraction--datasource-proxy-ssrf-to-mi` | `Microsoft.Dashboard/grafana/ActAsGrafanaEditor/action` — datasource-proxy SSRF-to-MI | Microsoft.Dashboard/grafana/ActAsGrafanaEditor/action | EXCLUDED | `azure-grafana-datasource-workspace-identity` NEEDS SCHEMA: exact execution or token retrieval for a named identity and a newly authorized action are unverified. |
| `az-privilege-escalation/az-managed-grafana-privesc.md#microsoftdashboardgrafanamanagedprivateendpointswrite--network-pivot-into-a-private-vnet` | `Microsoft.Dashboard/grafana/managedPrivateEndpoints/write` — network pivot into a private VNet | Microsoft.Dashboard/grafana/managedPrivateEndpoints/write | EXCLUDED | Network reachability only; no identity gain. |
| `az-privilege-escalation/az-managed-grafana-privesc.md#references` | References |  | STRUCTURAL | section/how-to heading; no technique |

## az-privilege-escalation/az-maps-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-maps-privesc.md#az---maps-privesc` | Az - Maps Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-maps-privesc.md#azure-maps` | Azure Maps |  | EXCLUDED | Introductory section. |
| `az-privilege-escalation/az-maps-privesc.md#microsoftmapsaccountslistkeysaction` | `Microsoft.Maps/accounts/listKeys/action` | Microsoft.Maps/accounts/listKeys/action | EXCLUDED | Maps data-plane shared key; no identity gain. |
| `az-privilege-escalation/az-maps-privesc.md#microsoftmapsaccountsregeneratekeyaction` | `Microsoft.Maps/accounts/regenerateKey/action` | Microsoft.Maps/accounts/regenerateKey/action | EXCLUDED | Rotates and returns the Maps shared key (data-plane credential, no identity); also DoS. Same as the excluded listKeys. |
| `az-privilege-escalation/az-maps-privesc.md#microsoftmapsaccountslistsasaction` | `Microsoft.Maps/accounts/listSas/action` | Microsoft.Maps/accounts/listSas/action | EXCLUDED | `azure-maps-listsas-attached-identity` NEEDS SCHEMA: exact bounded credential or workload execution to a named target and newly authorized action are unverified. |
| `az-privilege-escalation/az-maps-privesc.md#references` | References |  | STRUCTURAL | section/how-to heading; no technique |

## az-privilege-escalation/az-monitor-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-monitor-privesc.md#az---azure-monitor-privesc` | Az - Azure Monitor Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-monitor-privesc.md#azure-monitor` | Azure Monitor |  | EXCLUDED | Introductory section. |
| `az-privilege-escalation/az-monitor-privesc.md#microsoftinsightsactiongroupsread` | Microsoft.Insights/actionGroups/read | Microsoft.Insights/actionGroups/read | EXCLUDED | NEEDS SCHEMA: Exact signed callback, target automation identity, attacker-controlled invocation, and newly permitted action must be verified. |
| `az-privilege-escalation/az-monitor-privesc.md#microsoftinsightswebtestsread` | Microsoft.Insights/webtests/read | Microsoft.Insights/webtests/read | EXCLUDED | NEEDS SCHEMA: Exact credential in the stored request, its subject, usability, and newly permitted action must be verified. |
| `az-privilege-escalation/az-monitor-privesc.md#microsoftinsightscomponentsapikeysaction` | Microsoft.Insights/Components/ApiKeys/Action | Microsoft.Insights/Components/ApiKeys/Action | EXCLUDED | NEEDS SCHEMA: Exact Application Insights key scope and newly permitted telemetry action must be verified. |
| `az-privilege-escalation/az-monitor-privesc.md#microsoftinsightsgeneratelivetokenread` | Microsoft.Insights/generateLiveToken/read | Microsoft.Insights/generateLiveToken/read | EXCLUDED | NEEDS SCHEMA: Exact Live Metrics token scope and newly permitted stream action must be verified. |
| `az-privilege-escalation/az-monitor-privesc.md#microsoftinsightsmetricalertswrite--linked-reads` | Microsoft.Insights/metricAlerts/write (+ linked reads) | Microsoft.Insights/metricAlerts/write | EXCLUDED | NEEDS SCHEMA: Exact action-group receiver, controllable invocation, named automation principal, and newly authorized action must be verified; firing fixed logic alone is terminal. |
| `az-privilege-escalation/az-monitor-privesc.md#microsoftinsightsscheduledqueryruleswrite--the-same-trick-with-a-kql-alert` | Microsoft.Insights/scheduledQueryRules/write — the same trick with a KQL alert | Microsoft.Insights/scheduledQueryRules/write | EXCLUDED | NEEDS SCHEMA: Exact action-group receiver, controllable invocation, named automation principal, and newly authorized action must be verified; firing fixed logic alone is terminal. |
| `az-privilege-escalation/az-monitor-privesc.md#references` | References |  | STRUCTURAL | references |

## az-privilege-escalation/az-mysql-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-mysql-privesc.md#az---mysql-database-privesc` | Az - MySQL Database Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-mysql-privesc.md#mysql-databases` | MySQL Databases |  | EXCLUDED | Introductory section. |
| `az-privilege-escalation/az-mysql-privesc.md#mysql-database-privesc` | MySQL Database Privesc |  | STRUCTURAL | section/how-to heading; no technique |
| `az-privilege-escalation/az-mysql-privesc.md#microsoftdbformysqlflexibleserversread--microsoftdbformysqlflexibleserverswrite--microsoftdbformysqlflexibleserversdelete` | `Microsoft.DBforMySQL/flexibleServers/read` && `Microsoft.DBforMySQL/flexibleServers/write` && `Microsoft.DBforMySQL/flexibleServers/delete` | Microsoft.DBforMySQL/flexibleServers/delete,Microsoft.DBforMySQL/flexibleServers/read,Microsoft.DBforMySQL/flexibleServers/write | MAPPED | `azure-mysql-flexible-admin-password-reset` |
| `az-privilege-escalation/az-mysql-privesc.md#microsoftdbformysqlflexibleserversread-microsoftdbformysqlflexibleserverswrite-microsoftdbformysqlflexibleserversbackupsread` | `Microsoft.DBforMySQL/flexibleServers/read`, `Microsoft.DBforMySQL/flexibleServers/write`, `Microsoft.DBforMySQL/flexibleServers/backups/read` | Microsoft.DBforMySQL/flexibleServers/backups/read,Microsoft.DBforMySQL/flexibleServers/read,Microsoft.DBforMySQL/flexibleServers/write | EXCLUDED | Copies data into a new server; data access only (password reset path modelled separately). |
| `az-privilege-escalation/az-mysql-privesc.md#microsoftdbformysqlflexibleserversread-microsoftdbformysqlflexibleserverswrite-microsoftmanagedidentityuserassignedidentitiesassignaction-microsoftdbformysqlflexibleserversadministratorswrite--microsoftdbformysqlflexibleserversadministratorsread` | `Microsoft.DBforMySQL/flexibleServers/read`, `Microsoft.DBforMySQL/flexibleServers/write`, `Microsoft.ManagedIdentity/userAssignedIdentities/assign/action`, `Microsoft.DBforMySQL/flexibleServers/administrators/write` && `Microsoft.DBforMySQL/flexibleServers/administrators/read` | Microsoft.DBforMySQL/flexibleServers/administrators/read,Microsoft.DBforMySQL/flexibleServers/administrators/write,Microsoft.DBforMySQL/flexibleServers/read,Microsoft.DBforMySQL/flexibleServers/write,Microsoft.ManagedIdentity/userAssignedIdentities/assign/action | MAPPED | `azure-mysql-flexible-entra-admin-write` |
| `az-privilege-escalation/az-mysql-privesc.md#microsoftdbformysqlflexibleserversprivateendpointconnectionswrite--self-approve-a-private-endpoint` | `Microsoft.DBforMySQL/flexibleServers/privateEndpointConnections/write` — self-approve a private endpoint | Microsoft.DBforMySQL/flexibleServers/privateEndpointConnections/write | EXCLUDED | Network path only; data-plane access still needs the password-reset/Entra-admin entries. |
| `az-privilege-escalation/az-mysql-privesc.md#references` | References |  | STRUCTURAL | section/how-to heading; no technique |

## az-privilege-escalation/az-notification-hubs-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-notification-hubs-privesc.md#az---notification-hubs-privesc` | Az - Notification Hubs Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-notification-hubs-privesc.md#notification-hubs` | Notification Hubs |  | EXCLUDED | Introductory section. |
| `az-privilege-escalation/az-notification-hubs-privesc.md#shared-access-keys` | Shared-access keys |  | EXCLUDED | NEEDS SCHEMA: Exact hub authorization rule, usable key, and newly permitted send/listen/manage action must be verified. |
| `az-privilege-escalation/az-notification-hubs-privesc.md#platform-notification-service-credentials` | Platform Notification Service credentials |  | EXCLUDED | NEEDS SCHEMA: Exact third-party push service subject, usable credential, and newly permitted push action must be verified. |
| `az-privilege-escalation/az-notification-hubs-privesc.md#pns-credential-takeover-with-namespacesnotificationhubswrite` | PNS-credential takeover with `Namespaces/NotificationHubs/write` |  | EXCLUDED | NEEDS SCHEMA: Exact PNS service identity and newly authorized action after credential replacement must be verified. |
| `az-privilege-escalation/az-notification-hubs-privesc.md#key-less-push-with-notificationhubsdebugsendaction` | Key-less push with `NotificationHubs/debugSend/action` |  | STRUCTURAL | pointer to post-exploitation page |
| `az-privilege-escalation/az-notification-hubs-privesc.md#web-push-key-theft-with-notificationhubsvapidkeysread` | Web-push key theft with `NotificationHubs/vapidkeys/read` |  | EXCLUDED | NEEDS SCHEMA: Exact Web Push signing identity, usable key, and newly permitted push action must be verified. |
| `az-privilege-escalation/az-notification-hubs-privesc.md#references` | References |  | STRUCTURAL | references |

## az-privilege-escalation/az-pim-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-pim-privesc.md#az---pim-privesc` | Az - PIM Privesc |  | STRUCTURAL | title/reference/intro heading |
| `az-privilege-escalation/az-pim-privesc.md#privileged-identity-management-pim` | Privileged Identity Management (PIM) |  | EXCLUDED | Introductory text. |
| `az-privilege-escalation/az-pim-privesc.md#activate-an-eligible-role-in-model-jit-self-elevation` | Activate an eligible role (in-model JIT self-elevation) |  | MAPPED | `azure-entraid-pim-eligible-role-activation` |
| `az-privilege-escalation/az-pim-privesc.md#weaken-the-activation-gate` | Weaken the activation gate |  | EXCLUDED | Enabler (roleManagementPolicies write / RoleManagementPolicy.ReadWrite.*); removes approval or MFA but the privilege is still gained through eligibility, modelled in azure-entraid-pim-eligible-role-activation. Azure RBAC policy write belongs to the authorization catalog. |
| `az-privilege-escalation/az-pim-privesc.md#pim-for-groups-the-sneaky-path` | PIM for Groups (the sneaky path) |  | MAPPED | `azure-entraid-graph-pim-groups-active-assignment` `azure-entraid-pim-group-eligible-activation` |
| `az-privilege-escalation/az-pim-privesc.md#making-yourself-eligible-persistence-adjacent` | Making yourself eligible (persistence-adjacent) |  | EXCLUDED | Needs the same rights as an active assignment (Privileged Role Administrator / RoleManagement.ReadWrite.Directory, or Azure RBAC Owner/User Access Administrator), already modelled as direct edges; eligibility is persistence. |
| `az-privilege-escalation/az-pim-privesc.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-privilege-escalation/az-policy-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-policy-privesc.md#az---azure-policy-privesc` | Az - Azure Policy Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-policy-privesc.md#azure-policy` | Azure Policy |  | EXCLUDED | Introductory section. |
| `az-privilege-escalation/az-policy-privesc.md#the-dine--modify-remediation-identity-primitive` | The DINE / Modify remediation-identity primitive |  | EXCLUDED | Definition-rewrite branch NEEDS SCHEMA for exact assignment-to-MI join and remediation; resource role-assignment grant needs typed ABAC and observed grant proof. |
| `az-privilege-escalation/az-policy-privesc.md#hijack-an-existing-remediation-identity` | Hijack an existing remediation identity |  | EXCLUDED | Definition rewrite NEEDS SCHEMA for exact definition-to-assignment-to-MI join and observed remediation; parameter-only effects vary by definition. |
| `az-privilege-escalation/az-policy-privesc.md#turning-off-guardrails-is-itself-an-escalation-enabler` | Turning off guardrails is itself an escalation enabler |  | EXCLUDED | NEEDS SCHEMA: exact prior Deny, guardrail change, and post-change authorized action are required |
| `az-privilege-escalation/az-policy-privesc.md#references` | References |  | STRUCTURAL | references |

## az-privilege-escalation/az-postgresql-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-postgresql-privesc.md#az---postgresql-privesc` | Az - PostgreSQL Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-postgresql-privesc.md#postgresql-databases` | PostgreSQL Databases |  | EXCLUDED | Introductory section. |
| `az-privilege-escalation/az-postgresql-privesc.md#postgresql-privesc` | PostgreSQL Privesc |  | STRUCTURAL | section/how-to heading; no technique |
| `az-privilege-escalation/az-postgresql-privesc.md#microsoftdbforpostgresqlflexibleserversread-microsoftdbforpostgresqlflexibleserverswrite-microsoftdbforpostgresqlflexibleserversconfigurationswrite` | `Microsoft.DBforPostgreSQL/flexibleServers/read`, `Microsoft.DBforPostgreSQL/flexibleServers/write`, `Microsoft.DBforPostgreSQL/flexibleServers/configurations/write` | Microsoft.DBforPostgreSQL/flexibleServers/configurations/write,Microsoft.DBforPostgreSQL/flexibleServers/read,Microsoft.DBforPostgreSQL/flexibleServers/write | MAPPED | `azure-postgresql-flexible-admin-password-reset` |
| `az-privilege-escalation/az-postgresql-privesc.md#microsoftdbforpostgresqlflexibleserversread-microsoftdbforpostgresqlflexibleserverswrite-microsoftdbforpostgresqlflexibleserversbackupsread` | `Microsoft.DBforPostgreSQL/flexibleServers/read`, `Microsoft.DBforPostgreSQL/flexibleServers/write`, `Microsoft.DBforPostgreSQL/flexibleServers/backups/read` | Microsoft.DBforPostgreSQL/flexibleServers/backups/read,Microsoft.DBforPostgreSQL/flexibleServers/read,Microsoft.DBforPostgreSQL/flexibleServers/write | EXCLUDED | Data copy; password reset path modelled separately. |
| `az-privilege-escalation/az-postgresql-privesc.md#microsoftdbforpostgresqlflexibleserversread-microsoftdbforpostgresqlflexibleserverswrite-microsoftdbforpostgresqlflexibleserversadministratorswrite--microsoftdbforpostgresqlflexibleserversadministratorsread` | `Microsoft.DBforPostgreSQL/flexibleServers/read`, `Microsoft.DBforPostgreSQL/flexibleServers/write`, `Microsoft.DBforPostgreSQL/flexibleServers/administrators/write` && `Microsoft.DBforPostgreSQL/flexibleServers/administrators/read` | Microsoft.DBforPostgreSQL/flexibleServers/administrators/read,Microsoft.DBforPostgreSQL/flexibleServers/administrators/write,Microsoft.DBforPostgreSQL/flexibleServers/read,Microsoft.DBforPostgreSQL/flexibleServers/write | MAPPED | `azure-postgresql-flexible-entra-admin-write` |
| `az-privilege-escalation/az-postgresql-privesc.md#microsoftdbforpostgresqlflexibleserversstartltrbackupaction--long-term-retention-backup-exfil-to-attacker-storage-no-db-creds` | `Microsoft.DBforPostgreSQL/flexibleServers/startLtrBackup/action` — long-term-retention backup exfil to attacker storage (no DB creds) | Microsoft.DBforPostgreSQL/flexibleServers/ltrPreBackup/action,Microsoft.DBforPostgreSQL/flexibleServers/startLtrBackup/action | EXCLUDED | Data exfiltration; no identity gain. |
| `az-privilege-escalation/az-postgresql-privesc.md#microsoftdbforpostgresqlflexibleserversmigrationswrite--outbound-connectivity--ssrf-style-reachability-oracle` | `Microsoft.DBforPostgreSQL/flexibleServers/migrations/write` — outbound connectivity / SSRF-style reachability oracle | Microsoft.DBforPostgreSQL/flexibleServers/migrations/write | EXCLUDED | Network reconnaissance; no identity gain. |
| `az-privilege-escalation/az-postgresql-privesc.md#microsoftdbforpostgresqlflexibleserversprivateendpointconnectionswrite--self-approve-a-private-endpoint` | `Microsoft.DBforPostgreSQL/flexibleServers/privateEndpointConnections/write` — self-approve a private endpoint | Microsoft.DBforMySQL/flexibleServers/privateEndpointConnections/write,Microsoft.DBforPostgreSQL/flexibleServers/privateEndpointConnections/write | EXCLUDED | Network path only; data-plane access still needs the password-reset/Entra-admin entries. |
| `az-privilege-escalation/az-postgresql-privesc.md#references` | References |  | STRUCTURAL | section/how-to heading; no technique |

## az-privilege-escalation/az-purview-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-purview-privesc.md#az---purview-privesc` | Az - Purview Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-purview-privesc.md#purview` | Purview |  | EXCLUDED | Introductory section. |
| `az-privilege-escalation/az-purview-privesc.md#microsoftpurviewaccountslistkeysaction` | `Microsoft.Purview/accounts/listkeys/action` | Microsoft.Purview/accounts/listkeys/action | EXCLUDED | Event injection/read on metadata pipeline; no identity gain. |
| `az-privilege-escalation/az-purview-privesc.md#microsoftpurviewaccountsaddrootcollectionadminaction--arm-contributor-to-full-data-plane-takeover` | `Microsoft.Purview/accounts/addrootcollectionadmin/action` — ARM Contributor to full data-plane takeover | Microsoft.Authorization/*/write,Microsoft.Purview/accounts/addrootcollectionadmin/action | MAPPED | `azure-purview-add-root-collection-admin` |
| `az-privilege-escalation/az-purview-privesc.md#microsoftpurviewpolicyelementswrite--purview-access-policies-into-governed-sqlstorage` | `Microsoft.Purview/policyElements/write` — Purview access policies into governed SQL/Storage | Microsoft.Purview/policyElements/write | MAPPED | `azure-purview-policy-self-grant` |
| `az-privilege-escalation/az-purview-privesc.md#microsoftpurviewaccountskafkaconfigurationswrite--metadata-exfil--lineage-spoof` | `Microsoft.Purview/accounts/kafkaConfigurations/write` — metadata exfil / lineage spoof | Microsoft.Purview/accounts/kafkaConfigurations/write | EXCLUDED | Metadata exfiltration / lineage spoofing; no identity gain. |
| `az-privilege-escalation/az-purview-privesc.md#microsoftpurviewaccountswrite--network-open--confused-deputy-identity-swap` | `Microsoft.Purview/accounts/write` — network open / confused-deputy identity swap | Microsoft.Purview/accounts/write | EXCLUDED | Opening public network access grants no identity. Attaching a user-assigned identity the attacker already controls gives the attacker nothing new, and data-source grants made to the account's previous identity do not transfer; any other change only steers fixed Purview scan logic (confused deputy). |

## az-privilege-escalation/az-quantum-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-quantum-privesc.md#az---quantum-privesc` | Az - Quantum Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-quantum-privesc.md#azure-quantum` | Azure Quantum |  | EXCLUDED | Introductory section. |
| `az-privilege-escalation/az-quantum-privesc.md#workspace-api-key-disclosure-and-regeneration` | Workspace API-key disclosure and regeneration | Microsoft.Quantum/Workspaces/listKeys/action,Microsoft.Quantum/Workspaces/regenerateKey/action | EXCLUDED | NEEDS SCHEMA: Exact workspace key identity, usable credential, and newly permitted job action must be verified. |

## az-privilege-escalation/az-queue-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-queue-privesc.md#az---queue-storage-privesc` | Az - Queue Storage Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-queue-privesc.md#queue-storage` | Queue Storage |  | EXCLUDED | Introductory section; message reads are data access. |
| `az-privilege-escalation/az-queue-privesc.md#queue` | Queue |  | EXCLUDED | Data access and disruption; the only escalation is through a downstream consumer (excluded at |
| `az-privilege-escalation/az-queue-privesc.md#conditional-escalation-through-a-downstream-consumer` | Conditional escalation through a downstream consumer |  | EXCLUDED | `azure-queue-message-injection-consumer` NEEDS SCHEMA: exact written object or message, consumer binding and trigger, observed execution, and a newly obtained identity token or action are unverified. |
| `az-privilege-escalation/az-queue-privesc.md#references` | References |  | STRUCTURAL | references |

## az-privilege-escalation/az-redis-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-redis-privesc.md#az---azure-cache-for-redis-privesc` | Az - Azure Cache for Redis Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-redis-privesc.md#azure-cache-for-redis` | Azure Cache for Redis |  | EXCLUDED | Introductory section. |
| `az-privilege-escalation/az-redis-privesc.md#microsoftcacheredislistkeysaction` | `Microsoft.Cache/redis/listKeys/action` | Microsoft.Cache/redis/listKeys/action | EXCLUDED | NEEDS SCHEMA: bind the returned classic Redis key to the exact cache/default user, enabled key auth, successful data-plane authentication, and commands newly available to the caller. |
| `az-privilege-escalation/az-redis-privesc.md#microsoftcacheredisregeneratekeyaction` | `Microsoft.Cache/redis/regenerateKey/action` | Microsoft.Cache/redis/regenerateKey/action | EXCLUDED | NEEDS SCHEMA: bind the rotated classic Redis key to the exact cache/default user, enabled key auth, successful authentication, and newly effective commands; rotation alone is not escalation. |
| `az-privilege-escalation/az-redis-privesc.md#azure-managed-redis-database-keys` | Azure Managed Redis database keys |  | EXCLUDED | NEEDS SCHEMA: bind the list/rotated database key to the exact Managed Redis database/default user, enabled key auth, successful authentication, and newly effective commands. |

## az-privilege-escalation/az-relay-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-relay-privesc.md#az---azure-relay-privesc` | Az - Azure Relay Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-relay-privesc.md#azure-relay` | Azure Relay |  | EXCLUDED | Introductory section. |
| `az-privilege-escalation/az-relay-privesc.md#relay-sas-key-disclosure` | Relay SAS-key disclosure |  | EXCLUDED | NEEDS SCHEMA: Exact relay authorization rule, usable SAS key, and newly permitted send/listen action must be verified. |
| `az-privilege-escalation/az-relay-privesc.md#entra-rbac-relay-access-with-sendlisten-data-actions-bypasses-sas-key-disclosure` | Entra-RBAC relay access with send/listen data actions (bypasses SAS-key disclosure) |  | EXCLUDED | Send/listen on a hybrid connection or WCF relay is data-plane traffic and network-boundary reachability into the fronted service; no new Azure/Entra identity. |
| `az-privilege-escalation/az-relay-privesc.md#references` | References |  | STRUCTURAL | references |

## az-privilege-escalation/az-sentinel-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-sentinel-privesc.md#az---sentinel-privesc` | Az - Sentinel Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-sentinel-privesc.md#sentinel` | Sentinel |  | EXCLUDED | Introductory section. |
| `az-privilege-escalation/az-sentinel-privesc.md#automation-rule--playbook--managed-identity` | Automation rule → playbook → managed identity |  | EXCLUDED | The identity gain comes from Microsoft.Logic/workflows/write on the playbook, already modelled by azure-logicapp-workflow-write-existing-identity; the automation rule only supplies a run path (its run_path condition). |
| `az-privilege-escalation/az-sentinel-privesc.md#microsoftsecurityinsights-write--workspace-access` | `Microsoft.SecurityInsights/*` write + workspace access | Microsoft.SecurityInsights/* | EXCLUDED | Runs the playbook's existing, unmodified logic; confused-deputy invocation of fixed logic, not attacker-chosen execution as its identity. |
| `az-privilege-escalation/az-sentinel-privesc.md#kql-over-sensitive-tables` | KQL over sensitive tables |  | EXCLUDED | Moved to post-exploitation; Data read; any harvested secret is content-dependent and not derivable from RBAC. |
| `az-privilege-escalation/az-sentinel-privesc.md#references` | References |  | STRUCTURAL | references |

## az-privilege-escalation/az-service-fabric-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-service-fabric-privesc.md#az---service-fabric-privesc` | Az - Service Fabric Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-service-fabric-privesc.md#service-fabric` | Service Fabric |  | EXCLUDED | Introductory section. |
| `az-privilege-escalation/az-service-fabric-privesc.md#service-fabric-overview` | Service Fabric overview |  | EXCLUDED | Background section; techniques are modelled in azure/service_fabric.yaml. |
| `az-privilege-escalation/az-service-fabric-privesc.md#application-deploy--node-rce` | Application deploy → node RCE | Microsoft.Resources/deployments/*,Microsoft.ServiceFabric/clusters/applications/write,Microsoft.ServiceFabric/managedClusters/applicationTypes/write | EXCLUDED | NEEDS SCHEMA: The service-fabric node-VMSS link is explicitly uncollected, so application deployment cannot resolve an exact node managed identity or prove its token was exposed. |
| `az-privilege-escalation/az-service-fabric-privesc.md#cluster--client-certificate-theft--data-plane-admin` | Cluster / client certificate theft → data-plane admin | Microsoft.KeyVault/vaults/secrets/read | EXCLUDED | The certificate is a Service Fabric data-plane admin credential, not an Azure/Entra principal; its follow-on node code execution reaches the same node identities as azure-servicefabric-application-deploy-node-identity. Key Vault secret reads are catalogued in key_vault.yaml. |
| `az-privilege-escalation/az-service-fabric-privesc.md#cluster--node-type-create-or-modify` | Cluster / node-type create-or-modify | Microsoft.Compute/virtualMachineScaleSets/write,Microsoft.ServiceFabric/clusters/write,Microsoft.ServiceFabric/managedClusters/write | EXCLUDED | NEEDS SCHEMA: Node-type identity attachment alone does not give the source code execution on that node or prove an exact IMDS token and newly allowed action were obtained. |
| `az-privilege-escalation/az-service-fabric-privesc.md#managed-identity-token-theft-via-the-sf-token-service` | Managed-identity token theft via the SF token service | Microsoft.ManagedIdentity/userAssignedIdentities/*/assign/action | MAPPED | `azure-servicefabric-application-user-assigned-identity` |
| `az-privilege-escalation/az-service-fabric-privesc.md#references` | References |  | STRUCTURAL | references/enumeration |

## az-privilege-escalation/az-servicebus-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-servicebus-privesc.md#az---service-bus-privesc` | Az - Service Bus Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-servicebus-privesc.md#service-bus` | Service Bus |  | EXCLUDED | Introductory section. |
| `az-privilege-escalation/az-servicebus-privesc.md#authorization-rule-key-disclosure-and-rotation` | Authorization-rule key disclosure and rotation |  | EXCLUDED | Message read/injection. |
| `az-privilege-escalation/az-servicebus-privesc.md#microsoftservicebusnamespacesdisasterrecoveryconfigsauthorizationruleslistkeysaction` | Microsoft.ServiceBus/namespaces/disasterRecoveryConfigs/authorizationRules/listkeys/action | Microsoft.ServiceBus/namespaces/disasterRecoveryConfigs/authorizationRules/listkeys/action | EXCLUDED | Message read/injection. |
| `az-privilege-escalation/az-servicebus-privesc.md#microsoftservicebusnamespacesauthorizationruleswrite` | Microsoft.ServiceBus/namespaces/AuthorizationRules/write | Microsoft.ServiceBus/namespaces/AuthorizationRules/write | EXCLUDED | Message read/injection. |
| `az-privilege-escalation/az-servicebus-privesc.md#microsoftservicebusnamespacesqueuestopicsauthorizationruleslistkeysaction-or-microsoftservicebusnamespacesqueuestopicsauthorizationrulesregeneratekeysaction` | Microsoft.ServiceBus/namespaces/[queues\|topics]/authorizationRules/ListKeys/action OR Microsoft.ServiceBus/namespaces/[queues\|topics]/authorizationRules/regenerateKeys/action | Microsoft.ServiceBus/namespaces/[queues\|topics]/authorizationRules/ListKeys/action;Microsoft.ServiceBus/namespaces/[queues\|topics]/authorizationRules/regenerateKeys/action | EXCLUDED | Message read/injection. |
| `az-privilege-escalation/az-servicebus-privesc.md#microsoftservicebusnamespacesqueuestopicsauthorizationruleswrite` | Microsoft.ServiceBus/namespaces/[queues\|topics]/authorizationRules/write | Microsoft.ServiceBus/namespaces/[queues\|topics]/authorizationRules/write | EXCLUDED | Message read/injection. |
| `az-privilege-escalation/az-servicebus-privesc.md#microsoftservicebusnamespaceswrite--microsoftservicebusnamespacesread-if-az-cli-is-used` | Microsoft.ServiceBus/namespaces/write (& Microsoft.ServiceBus/namespaces/read if az cli is used) | Microsoft.ServiceBus/namespaces/write;Microsoft.ServiceBus/namespaces/read | EXCLUDED | Control weakening; no identity. |
| `az-privilege-escalation/az-servicebus-privesc.md#send-messages-with-keys-microsoftservicebusnamespacesqueuestopicsauthorizationruleslistkeysaction-or-microsoftservicebusnamespacesqueuestopicsauthorizationrulesregeneratekeysaction` | Send Messages with keys (Microsoft.ServiceBus/namespaces/[queues\|topics]/authorizationRules/ListKeys/action OR Microsoft.ServiceBus/namespaces/[queues\|topics]/authorizationRules/regenerateKeys/action) | Microsoft.ServiceBus/namespaces/[queues\|topics]/authorizationRules/ListKeys/action;Microsoft.ServiceBus/namespaces/[queues\|topics]/authorizationRules/regenerateKeys/action | EXCLUDED | SAS data-plane credential used for message injection; no Azure/Entra identity. Downstream consumer behaviour runs fixed logic. |
| `az-privilege-escalation/az-servicebus-privesc.md#receive-with-keys-microsoftservicebusnamespacesqueuestopicsauthorizationruleslistkeysaction-or-microsoftservicebusnamespacesqueuestopicsauthorizationrulesregeneratekeysaction` | Receive with keys (Microsoft.ServiceBus/namespaces/[queues\|topics]/authorizationRules/ListKeys/action OR Microsoft.ServiceBus/namespaces/[queues\|topics]/authorizationRules/regenerateKeys/action) | Microsoft.ServiceBus/namespaces/[queues\|topics]/authorizationRules/ListKeys/action;Microsoft.ServiceBus/namespaces/[queues\|topics]/authorizationRules/regenerateKeys/action | EXCLUDED | Message data read with a SAS data-plane credential; no Azure/Entra identity. |
| `az-privilege-escalation/az-servicebus-privesc.md#send-messages-dataactions-microsoftservicebusnamespacesmessagessendaction` | Send Messages. DataActions: `Microsoft.ServiceBus/namespaces/messages/send/action` | Microsoft.ServiceBus/namespaces/messages/send/action | EXCLUDED | `azure-servicebus-message-injection-consumer` NEEDS SCHEMA: exact written object or message, consumer binding and trigger, observed execution, and a newly obtained identity token or action are unverified. |
| `az-privilege-escalation/az-servicebus-privesc.md#receive-messages-dataactions-microsoftservicebusnamespacesmessagesreceiveaction` | Receive Messages. DataActions: `Microsoft.ServiceBus/namespaces/messages/receive/action` | Microsoft.ServiceBus/namespaces/messages/receive/action | EXCLUDED | Message data read; no new identity. |
| `az-privilege-escalation/az-servicebus-privesc.md#references` | References |  | STRUCTURAL | references |

## az-privilege-escalation/az-signalr-web-pubsub-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-signalr-web-pubsub-privesc.md#az---signalr-and-web-pubsub-privesc` | Az - SignalR and Web PubSub Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-signalr-web-pubsub-privesc.md#signalr-and-web-pubsub` | SignalR and Web PubSub |  | EXCLUDED | Introductory section. |
| `az-privilege-escalation/az-signalr-web-pubsub-privesc.md#access-key-disclosure-and-message-injection` | Access-key disclosure and message injection |  | EXCLUDED | Real-time message control; application-dependent. |
| `az-privilege-escalation/az-signalr-web-pubsub-privesc.md#signalr-temporary-signing-material-with-only-authaccesskeyaction` | SignalR temporary signing material with only `auth/accessKey/action` |  | EXCLUDED | Real-time message control; application-dependent. |
| `az-privilege-escalation/az-signalr-web-pubsub-privesc.md#targeted-client-message-injection` | Targeted client message injection |  | EXCLUDED | Message injection; escalation depends on downstream consumer logic, not modelable from RBAC. |
| `az-privilege-escalation/az-signalr-web-pubsub-privesc.md#web-pubsub-client-token-minimum-pair` | Web PubSub client-token minimum pair |  | EXCLUDED | Application client connection only. |
| `az-privilege-escalation/az-signalr-web-pubsub-privesc.md#microsoftsignalrservicewebpubsubhubswrite---redirect-future-user-events` | `Microsoft.SignalRService/WebPubSub/hubs/write` - Redirect future user events | Microsoft.SignalRService/WebPubSub/hubs/write | EXCLUDED | Event exfiltration; no identity. |
| `az-privilege-escalation/az-signalr-web-pubsub-privesc.md#microsoftsignalrservicesignalrwrite---upstream-repoint-event-exfil--mi-token-ssrf` | `Microsoft.SignalRService/SignalR/write` - Upstream repoint (event exfil + MI-token SSRF) | Microsoft.SignalRService/SignalR/write | EXCLUDED | `azure-signalr-upstream-managed-identity-token` NEEDS SCHEMA: exact token audience, triggered event, delivered token, and new action for a named MI are unverified. |
| `az-privilege-escalation/az-signalr-web-pubsub-privesc.md#managed-identity-attach-via-signalrwrite-or-webpubsubwrite` | Managed-identity attach via `SignalR/write` or `WebPubSub/write` |  | EXCLUDED | `azure-signalr-assign-user-assigned-identity` NEEDS SCHEMA: exact attach, event, delivered token, and new action for a named UAI are unverified. |
| `az-privilege-escalation/az-signalr-web-pubsub-privesc.md#untargeted-broadcastgroupuser-injection` | Untargeted broadcast/group/user injection |  | EXCLUDED | Data-plane message injection to clients; no Azure/Entra identity. |
| `az-privilege-escalation/az-signalr-web-pubsub-privesc.md#microsoftsignalrservicesignalrserverconnectionwrite---impersonate-the-hub-application-server` | `Microsoft.SignalRService/SignalR/serverConnection/write` - Impersonate the hub application server | Microsoft.SignalRService/SignalR/serverConnection/write | EXCLUDED | NEEDS SCHEMA: serverConnection/write can impersonate a SignalR hub server, but the catalog lacks an exact server identity, newly authorized hub operation, and prior-absence proof; message injection alone is a data-plane action. |
| `az-privilege-escalation/az-signalr-web-pubsub-privesc.md#microsoftsignalrservicewebpubsubauthaccesskeyaction---web-pubsub-temporary-signing-material` | `Microsoft.SignalRService/WebPubSub/auth/accessKey/action` - Web PubSub temporary signing material | Microsoft.SignalRService/WebPubSub/auth/accessKey/action | EXCLUDED | NEEDS SCHEMA: signing material can mint Web PubSub client tokens with bounded roles, but the exact client subject, token scope, usable credential, and newly permitted operation are not verified. |
| `az-privilege-escalation/az-signalr-web-pubsub-privesc.md#live-trace-eavesdropping-with-signalrlivetraceread` | Live-trace eavesdropping with `SignalR/livetrace/read` |  | EXCLUDED | Read-only connection and traffic metadata disclosure. |
| `az-privilege-escalation/az-signalr-web-pubsub-privesc.md#references` | References |  | STRUCTURAL | references |

## az-privilege-escalation/az-speech-services-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-speech-services-privesc.md#az---speech-services-privesc` | Az - Speech Services Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-speech-services-privesc.md#azure-ai-speech` | Azure AI Speech |  | STRUCTURAL | pointer to post-exploitation page |
| `az-privilege-escalation/az-speech-services-privesc.md#batch-transcription-content-disclosure` | Batch-transcription content disclosure | Microsoft.CognitiveServices/accounts/SpeechServices/speechrest/transcriptions/files/read,Microsoft.CognitiveServices/accounts/SpeechServices/speechrest/transcriptions/read | STRUCTURAL | pointer to post-exploitation page |
| `az-privilege-escalation/az-speech-services-privesc.md#authentication-and-endpoint-selection` | Authentication and endpoint selection |  | STRUCTURAL | pointer to post-exploitation page |
| `az-privilege-escalation/az-speech-services-privesc.md#enumerate-jobs` | Enumerate jobs | Microsoft.CognitiveServices/accounts/SpeechServices/speechrest/transcriptions/read | STRUCTURAL | pointer to post-exploitation page |
| `az-privilege-escalation/az-speech-services-privesc.md#recover-transcript-files` | Recover transcript files | Microsoft.CognitiveServices/accounts/SpeechServices/speechrest/transcriptions/files/read | STRUCTURAL | pointer to post-exploitation page |
| `az-privilege-escalation/az-speech-services-privesc.md#references` | References |  | STRUCTURAL | pointer to post-exploitation page |

## az-post-exploitation/az-speech-services-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-speech-services-post-exploitation.md#az---speech-services-post-exploitation` | Az - Speech Services Post Exploitation |  | STRUCTURAL | post-exploitation page title |
| `az-post-exploitation/az-speech-services-post-exploitation.md#azure-ai-speech` | Azure AI Speech |  | EXCLUDED | Introductory section. |
| `az-post-exploitation/az-speech-services-post-exploitation.md#batch-transcription-content-disclosure` | Batch-transcription content disclosure | Microsoft.CognitiveServices/accounts/SpeechServices/speechrest/transcriptions/files/read,Microsoft.CognitiveServices/accounts/SpeechServices/speechrest/transcriptions/read | EXCLUDED | Data read. |
| `az-post-exploitation/az-speech-services-post-exploitation.md#authentication-and-endpoint-selection` | Authentication and endpoint selection |  | SUBSECTION | of #batch-transcription-content-disclosure: EXCLUDED Data read. |
| `az-post-exploitation/az-speech-services-post-exploitation.md#enumerate-jobs` | Enumerate jobs | Microsoft.CognitiveServices/accounts/SpeechServices/speechrest/transcriptions/read | SUBSECTION | of #batch-transcription-content-disclosure: EXCLUDED Data read. |
| `az-post-exploitation/az-speech-services-post-exploitation.md#recover-transcript-files` | Recover transcript files | Microsoft.CognitiveServices/accounts/SpeechServices/speechrest/transcriptions/files/read | SUBSECTION | of #batch-transcription-content-disclosure: EXCLUDED Data read. |
| `az-post-exploitation/az-speech-services-post-exploitation.md#references` | References |  | STRUCTURAL | section/how-to heading; no technique |

## az-privilege-escalation/az-spring-apps-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-spring-apps-privesc.md#az---spring-apps-privesc` | Az - Spring Apps Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-spring-apps-privesc.md#azure-spring-apps` | Azure Spring Apps |  | EXCLUDED | Introductory section. |
| `az-privilege-escalation/az-spring-apps-privesc.md#spring-apps-overview` | Spring Apps overview |  | EXCLUDED | Background section; techniques are modelled in azure/spring_apps.yaml. |
| `az-privilege-escalation/az-spring-apps-privesc.md#app-deploy-rce--managed-identity-theft-marquee` | App-deploy RCE + managed-identity theft (marquee) | Microsoft.AppPlatform/Spring/apps/deployments/write,Microsoft.AppPlatform/Spring/apps/getResourceUploadUrl/action | MAPPED | `azure-springapps-deployment-write-app-identity` `azure-springapps-app-write-user-assigned-identity` |
| `az-privilege-escalation/az-spring-apps-privesc.md#rce-via-jvmoptions--environment-variables-settings-only-no-artifact-upload` | RCE via `jvmOptions` / environment variables (settings-only, no artifact upload) | Microsoft.AppPlatform/Spring/apps/deployments/write | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-spring-apps-privesc.md#app-deploy-rce--managed-identity-theft-marquee` |
| `az-privilege-escalation/az-spring-apps-privesc.md#listtestkeys--public-test-endpoints` | listTestKeys / public test endpoints | Microsoft.AppPlatform/Spring/listTestKeys/action | EXCLUDED | Unauthenticated HTTP reach to apps and possible secret disclosure through exposed actuator routes; content-dependent, no Azure/Entra identity derivable from RBAC. |
| `az-privilege-escalation/az-spring-apps-privesc.md#microsoftappplatformspringregeneratetestkeyaction` | `Microsoft.AppPlatform/Spring/regenerateTestKey/action` | Microsoft.AppPlatform/Spring/regenerateTestKey/action | EXCLUDED | Same test-endpoint key as listTestKeys (returned on rotation) plus DoS; no Azure/Entra identity. |
| `az-privilege-escalation/az-spring-apps-privesc.md#microsoftappplatformspringapmslistsecretkeysaction` | `Microsoft.AppPlatform/Spring/apms/listSecretKeys/action` | Microsoft.AppPlatform/Spring/apms/listSecretKeys/action | EXCLUDED | Telemetry-backend credentials (Application Insights connection string or third-party APM keys); data access, no Azure/Entra identity. |
| `az-privilege-escalation/az-spring-apps-privesc.md#config-server--bindings--secret-exposure` | Config server / bindings / secret exposure | Microsoft.AppPlatform/Spring/configServers/write | EXCLUDED | Configuration poisoning and secret disclosure whose result depends on application behaviour and secret contents; no code runs as the app identity through these actions alone and nothing is derivable from RBAC. |
| `az-privilege-escalation/az-spring-apps-privesc.md#custom-container--build-service-supply-chain` | Custom container / build-service supply chain |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-spring-apps-privesc.md#app-deploy-rce--managed-identity-theft-marquee` |
| `az-privilege-escalation/az-spring-apps-privesc.md#references` | References |  | STRUCTURAL | references/enumeration |

## az-privilege-escalation/az-sql-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-sql-privesc.md#az---sql-database-privesc` | Az - SQL Database Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-sql-privesc.md#sql` | SQL |  | EXCLUDED | Introductory section. |
| `az-privilege-escalation/az-sql-privesc.md#sql-database-privesc` | SQL Database Privesc |  | STRUCTURAL | section/how-to heading; no technique |
| `az-privilege-escalation/az-sql-privesc.md#microsoftsqlserversread--microsoftsqlserverswrite` | `Microsoft.Sql/servers/read` && `Microsoft.Sql/servers/write` | Microsoft.ManagedIdentity/userAssignedIdentities/assign/action,Microsoft.Sql/servers/read,Microsoft.Sql/servers/write | MAPPED | `azure-sql-server-admin-password-reset` |
| `az-privilege-escalation/az-sql-privesc.md#microsoftsqlserversfirewallruleswrite` | `Microsoft.Sql/servers/firewallRules/write` | Microsoft.Sql/servers/firewallRules/write | EXCLUDED | Network reachability only. |
| `az-privilege-escalation/az-sql-privesc.md#microsoftsqlserversipv6firewallruleswrite` | `Microsoft.Sql/servers/ipv6FirewallRules/write` | Microsoft.Sql/servers/ipv6FirewallRules/write | EXCLUDED | Network reachability only. |
| `az-privilege-escalation/az-sql-privesc.md#microsoftsqlserversadministratorswrite--microsoftsqlserversadministratorsread` | `Microsoft.Sql/servers/administrators/write` && `Microsoft.Sql/servers/administrators/read` | Microsoft.Sql/servers/administrators/read,Microsoft.Sql/servers/administrators/write | MAPPED | `azure-sql-server-entra-admin-write` |
| `az-privilege-escalation/az-sql-privesc.md#microsoftsqlserversazureadonlyauthenticationswrite--microsoftsqlserversazureadonlyauthenticationsread` | `Microsoft.Sql/servers/azureADOnlyAuthentications/write` && `Microsoft.Sql/servers/azureADOnlyAuthentications/read` | Microsoft.Sql/servers/azureADOnlyAuthentications/read,Microsoft.Sql/servers/azureADOnlyAuthentications/write | EXCLUDED | Control weakening; used as condition of password reset entry. |
| `az-privilege-escalation/az-sql-privesc.md#microsoftsqlserversdatabasesdatamaskingpolicieswrite` | `Microsoft.Sql/servers/databases/dataMaskingPolicies/write` | Microsoft.Sql/servers/databases/dataMaskingPolicies/write | EXCLUDED | Data exposure control. |
| `az-privilege-escalation/az-sql-privesc.md#remove-row-level-security` | Remove Row-Level Security |  | EXCLUDED | Data-plane SQL permission; not RBAC. |
| `az-privilege-escalation/az-sql-privesc.md#elastic-jobs-run-arbitrary-t-sql-through-jobagentsjobsstepswrite--executionswrite` | Elastic Jobs: run arbitrary T-SQL through `jobAgents/jobs/steps/write` + `executions/write` | Microsoft.Sql/servers/jobAgents/jobs/steps/write | EXCLUDED | Reaches a SQL login of unknown privilege, not an Azure principal or necessarily admin. |
| `az-privilege-escalation/az-sql-privesc.md#data-plane-escalation-azure-sql-fixed-server-roles-impersonate-db_owner` | Data-plane escalation: Azure-SQL fixed server roles, IMPERSONATE, db_owner |  | EXCLUDED | NEEDS SCHEMA: T-SQL IMPERSONATE and role grants can create exact SQL principal or permission gains, but the catalog lacks the source SQL login, target login or role, and effective before/after permissions. |
| `az-privilege-escalation/az-sql-privesc.md#microsoftsqlserversvirtualnetworkruleswrite--microsoftsqlserversoutboundfirewallruleswrite` | `Microsoft.Sql/servers/virtualNetworkRules/write` && `Microsoft.Sql/servers/outboundFirewallRules/write` | Microsoft.Sql/servers/outboundFirewallRules/write,Microsoft.Sql/servers/virtualNetworkRules/write | EXCLUDED | Network reachability and exfiltration enablement; no identity gain (network_reachable condition of the SQL admin entries). |
| `az-privilege-escalation/az-sql-privesc.md#references` | References |  | STRUCTURAL | section/how-to heading; no technique |

## az-privilege-escalation/az-sre-agent-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-sre-agent-privesc.md#az---azure-sre-agent-privesc` | Az - Azure SRE Agent Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-sre-agent-privesc.md#azure-sre-agent` | Azure SRE Agent |  | STRUCTURAL | section grouping heading |
| `az-privilege-escalation/az-sre-agent-privesc.md#microsoftappagentslistsecretsaction` | `Microsoft.App/agents/listSecrets/action` | Microsoft.App/agents/listSecrets/action | EXCLUDED | Credential disclosure with unestablished downstream use (page says impact unpromoted). |
| `az-privilege-escalation/az-sre-agent-privesc.md#microsoftappagentsdataconnectorslistsecretsaction` | `Microsoft.App/agents/dataconnectors/listSecrets/action` | Microsoft.App/agents/dataconnectors/listSecrets/action | EXCLUDED | NEEDS SCHEMA: returned connector secrets may authenticate a downstream identity, but exact subject, usable credential, newly permitted action, and prior-absence proof are not verified. |
| `az-privilege-escalation/az-sre-agent-privesc.md#drive-the-agents-managed-identity--instruction--tool-config-injection-agentsthreads-agentswrite-` | Drive the agent's managed identity — instruction / tool-config injection (`agents/threads`, `agents/write`, ...) | Microsoft.App/agents/dataconnectors/write,Microsoft.App/agents/memory/write,Microsoft.App/agents/scheduledtasks/write,Microsoft.App/agents/threads/approve/action,Microsoft.App/agents/threads/write,Microsoft.App/agents/write | EXCLUDED | NEEDS SCHEMA: exact agent run mode, accepted tool invocation, and newly authorized action by the named identity are uncollected. |
| `az-privilege-escalation/az-sre-agent-privesc.md#references` | References |  | STRUCTURAL | section/how-to heading; no technique |

## az-privilege-escalation/az-static-web-apps-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-static-web-apps-privesc.md#az---static-web-apps-privesc` | Az - Static Web Apps Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-static-web-apps-privesc.md#az-static-web-apps` | Az Static Web Apps |  | EXCLUDED | Introductory section. |
| `az-privilege-escalation/az-static-web-apps-privesc.md#azure-static-web-apps` | Azure Static Web Apps |  | STRUCTURAL | section grouping heading; techniques are its subsections |
| `az-privilege-escalation/az-static-web-apps-privesc.md#microsoftwebstaticsitessnippetswrite` | Microsoft.Web/staticSites/snippets/write | Microsoft.Web/staticSites/snippets/write | EXCLUDED | NEEDS SCHEMA: Exact authenticated visitor principal, credential/session capture, and newly authorized action must be verified; generic client-side injection alone is terminal. |
| `az-privilege-escalation/az-static-web-apps-privesc.md#read-configured-third-party-credentials` | Read Configured Third Party Credentials | Microsoft.Web/sourcecontrols,Microsoft.Web/sourcecontrols/read | EXCLUDED | NEEDS SCHEMA: Exact GitHub or other source-control credential, subject, usability, and newly permitted action must be verified. |
| `az-privilege-escalation/az-static-web-apps-privesc.md#overwrite-file---overwrite-routes-html-js` | Overwrite file - Overwrite routes, HTML, JS... |  | EXCLUDED | NEEDS SCHEMA: Exact source-control or application principal, attacker-controlled file execution, and newly authorized action must be verified. |
| `az-privilege-escalation/az-static-web-apps-privesc.md#microsoftwebstaticsitesconfigwrite` | Microsoft.Web/staticSites/config/write | Microsoft.Web/staticSites/config/write | EXCLUDED | Content access control only. |
| `az-privilege-escalation/az-static-web-apps-privesc.md#microsoftwebstaticsiteslistsecretsaction` | Microsoft.Web/staticSites/listSecrets/action | Microsoft.Web/staticSites/listSecrets/action | EXCLUDED | NEEDS SCHEMA: Exact deployment key subject, usability, and newly permitted deployment action must be verified. |
| `az-privilege-escalation/az-static-web-apps-privesc.md#microsoftwebstaticsiteswrite` | Microsoft.Web/staticSites/write | Microsoft.Web/staticSites/write | EXCLUDED | Static content deployment; no managed identity reached. |
| `az-privilege-escalation/az-static-web-apps-privesc.md#microsoftwebstaticsitesresetapikeyaction` | Microsoft.Web/staticSites/resetapikey/action | Microsoft.Web/staticSites/resetapikey/action | EXCLUDED | Disruption. |
| `az-privilege-escalation/az-static-web-apps-privesc.md#microsoftwebstaticsitescreateinvitationaction` | Microsoft.Web/staticSites/createInvitation/action | Microsoft.Web/staticSites/createInvitation/action | EXCLUDED | NEEDS SCHEMA: Exact invited application user, assigned app role, and before/after permitted action must be verified. |
| `az-privilege-escalation/az-static-web-apps-privesc.md#pull-requests` | Pull Requests |  | EXCLUDED | Repository-level abuse; no Azure identity. |
| `az-privilege-escalation/az-static-web-apps-privesc.md#references` | References |  | STRUCTURAL | references/enumeration |

## az-privilege-escalation/az-storage-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-storage-privesc.md#az---storage-privesc` | Az - Storage Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-storage-privesc.md#storage-accounts--blobs` | Storage Accounts & Blobs |  | EXCLUDED | Introductory section. |
| `az-privilege-escalation/az-storage-privesc.md#storage-privesc` | Storage Privesc |  | STRUCTURAL | section grouping heading |
| `az-privilege-escalation/az-storage-privesc.md#microsoftstoragestorageaccountslistkeysaction` | `Microsoft.Storage/storageAccounts/listkeys/action` | Microsoft.Storage/storageAccounts/listkeys/action | EXCLUDED | Storage data access; no identity gain. Function App content-storage escalation is modelled in functions.yaml. |
| `az-privilege-escalation/az-storage-privesc.md#microsoftstoragestorageaccountsregeneratekeyaction` | `Microsoft.Storage/storageAccounts/regenerateKey/action` | Microsoft.Storage/storageAccounts/regenerateKey/action | EXCLUDED | Storage data access; no identity gain. |
| `az-privilege-escalation/az-storage-privesc.md#microsoftstoragestorageaccountslistaccountsasaction` | `Microsoft.Storage/storageAccounts/listAccountSas/action` | Microsoft.Storage/storageAccounts/listAccountSas/action | EXCLUDED | Storage data access; no identity gain. |
| `az-privilege-escalation/az-storage-privesc.md#microsoftstoragestorageaccountslistservicesasaction` | `Microsoft.Storage/storageAccounts/listServiceSas/action` | Microsoft.Storage/storageAccounts/listServiceSas/action | EXCLUDED | Storage data access; no identity gain. |
| `az-privilege-escalation/az-storage-privesc.md#service-user-delegation-keys-blob-file-queue-and-table` | Service user-delegation keys (Blob, File, Queue, and Table) |  | EXCLUDED | Storage data access; no identity gain. |
| `az-privilege-escalation/az-storage-privesc.md#microsoftstoragestorageaccountswrite` | `Microsoft.Storage/storageAccounts/write` | Microsoft.Storage/storageAccounts/write | EXCLUDED | Control weakening only. |
| `az-privilege-escalation/az-storage-privesc.md#blobs-specific-privesc` | Blobs Specific privesc |  | STRUCTURAL | section grouping heading |
| `az-privilege-escalation/az-storage-privesc.md#poison-a-privileged-consumer-with-microsoftstoragestorageaccountsblobservicescontainersblobswrite` | Poison a privileged consumer with `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write` | Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write | EXCLUDED | `azure-storage-blob-poisoning-consumer` NEEDS SCHEMA: exact written object or message, consumer binding and trigger, observed execution, and a newly obtained identity token or action are unverified. |
| `az-privilege-escalation/az-storage-privesc.md#hns-acl-takeover-and-blob-super-user-data-action` | HNS ACL takeover and Blob super-user data action |  | MAPPED | `azure-storage-adls-acl-self-grant` |
| `az-privilege-escalation/az-storage-privesc.md#operational-blob-backup-rollback-with-microsoftdataprotectionbackupvaultsbackupinstancesrestoreaction` | Operational Blob backup rollback with `Microsoft.DataProtection/backupVaults/backupInstances/restore/action` | Microsoft.DataProtection/backupVaults/backupInstances/restore/action | EXCLUDED | Data integrity/recovery; no identity gain. |
| `az-privilege-escalation/az-storage-privesc.md#microsoftstoragestorageaccountsblobservicescontainersimmutabilitypolicieswrite--microsoftstoragestorageaccountsblobservicescontainersimmutabilitypoliciesdelete` | `Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies/write` \| `Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies/delete` | Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies/write;Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies/delete | EXCLUDED | Data retention control. |
| `az-privilege-escalation/az-storage-privesc.md#file-shares-specific-privesc` | File shares specific privesc |  | STRUCTURAL | section grouping heading |
| `az-privilege-escalation/az-storage-privesc.md#microsoftstoragestorageaccountsfileservicestakeownershipaction` | `Microsoft.Storage/storageAccounts/fileServices/takeOwnership/action` | Microsoft.Storage/storageAccounts/fileServices/takeOwnership/action | EXCLUDED | Storage data access; no identity gain. |
| `az-privilege-escalation/az-storage-privesc.md#microsoftstoragestorageaccountsfileservicesfilesharesfilesmodifypermissionsaction` | `Microsoft.Storage/storageAccounts/fileServices/fileshares/files/modifypermissions/action` | Microsoft.Storage/storageAccounts/fileServices/fileshares/files/modifypermissions/action | MAPPED | `azure-storage-files-acl-self-grant` |
| `az-privilege-escalation/az-storage-privesc.md#microsoftstoragestorageaccountsfileservicesfilesharesfilesactassuperuseraction` | `Microsoft.Storage/storageAccounts/fileServices/fileshares/files/actassuperuser/action` | Microsoft.Storage/storageAccounts/fileServices/fileshares/files/actassuperuser/action | EXCLUDED | Storage data access; no identity gain. |
| `az-privilege-escalation/az-storage-privesc.md#azure-files-and-local-user-credential-boundaries` | Azure Files and local-user credential boundaries |  | EXCLUDED | Page states not standalone primitives. |
| `az-privilege-escalation/az-storage-privesc.md#microsoftstoragestorageaccountslocaluserswrite-microsoftstoragestorageaccountslocalusersread` | `Microsoft.Storage/storageAccounts/localusers/write (Microsoft.Storage/storageAccounts/localusers/read)` | Microsoft.Storage/storageAccounts/localusers/write;Microsoft.Storage/storageAccounts/localusers/read | MAPPED | `azure-audit-microsoftstoragestorageaccountslocaluserswrite-microsoftstoragestorageac` |
| `az-privilege-escalation/az-storage-privesc.md#microsoftstoragestorageaccountslocalusersregeneratepasswordaction` | `Microsoft.Storage/storageAccounts/localusers/regeneratePassword/action` | Microsoft.Storage/storageAccounts/localusers/regeneratePassword/action | MAPPED | `azure-audit-microsoftstoragestorageaccountslocalusersregeneratepasswordaction` |
| `az-privilege-escalation/az-storage-privesc.md#microsoftstoragestorageaccountsrestoreblobrangesaction` | `Microsoft.Storage/storageAccounts/restoreBlobRanges/action` | Microsoft.Storage/storageAccounts/restoreBlobRanges/action | EXCLUDED | Data recovery. |
| `az-privilege-escalation/az-storage-privesc.md#soft-deleted-containers-and-blobs-via-account-keys` | Soft-deleted containers and blobs via account keys |  | EXCLUDED | Data recovery. |
| `az-privilege-escalation/az-storage-privesc.md#microsoftstoragestorageaccountsfileservicessharesrestoreaction--microsoftstoragestorageaccountsread` | `Microsoft.Storage/storageAccounts/fileServices/shares/restore/action` && `Microsoft.Storage/storageAccounts/read` | Microsoft.Storage/storageAccounts/fileServices/shares/restore/action;Microsoft.Storage/storageAccounts/read | EXCLUDED | Data recovery. |
| `az-privilege-escalation/az-storage-privesc.md#references` | References |  | STRUCTURAL | references |

## az-privilege-escalation/az-stream-analytics-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-stream-analytics-privesc.md#az---stream-analytics-privesc` | Az - Stream Analytics Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-stream-analytics-privesc.md#stream-analytics` | Stream Analytics |  | STRUCTURAL | pointer to post-exploitation page |
| `az-privilege-escalation/az-stream-analytics-privesc.md#sample-private-input-events` | Sample private input events | Microsoft.StreamAnalytics/streamingjobs/inputs/OperationResults/read,Microsoft.StreamAnalytics/streamingjobs/inputs/Sample/action | STRUCTURAL | pointer to post-exploitation page |
| `az-privilege-escalation/az-stream-analytics-privesc.md#redirect-a-running-jobs-output-sink-with-stop--outputswrite--start` | Redirect a running job's output sink with `Stop` + `outputs/Write` + `Start` | Microsoft.StreamAnalytics/streamingjobs/Start/action,Microsoft.StreamAnalytics/streamingjobs/Stop/action,Microsoft.StreamAnalytics/streamingjobs/outputs/Write | STRUCTURAL | pointer to post-exploitation page |
| `az-privilege-escalation/az-stream-analytics-privesc.md#full-job-rewrite--managed-identity-attach-with-streamingjobswrite` | Full-job rewrite + managed-identity attach with `streamingjobs/Write` | Microsoft.ManagedIdentity/userAssignedIdentities/*/assign/action,Microsoft.StreamAnalytics/*,Microsoft.StreamAnalytics/streamingjobs/Write | STRUCTURAL | pointer to post-exploitation page |
| `az-privilege-escalation/az-stream-analytics-privesc.md#msi-backed-confused-deputy-source-read-with-inputswrite` | MSI-backed confused-deputy source read with `inputs/Write` | Microsoft.StreamAnalytics/streamingjobs/inputs/Write | STRUCTURAL | pointer to post-exploitation page |
| `az-privilege-escalation/az-stream-analytics-privesc.md#azure-ml-udf-endpoint-repoint-with-functionswrite` | Azure ML UDF endpoint repoint with `functions/Write` | Microsoft.StreamAnalytics/streamingjobs/functions/Write | STRUCTURAL | pointer to post-exploitation page |
| `az-privilege-escalation/az-stream-analytics-privesc.md#job-less-egress--credential-validation-proxy-with-locationssampleinputaction` | Job-less egress / credential-validation proxy with `locations/SampleInput/action` | Microsoft.StreamAnalytics/locations/SampleInput/action | STRUCTURAL | pointer to post-exploitation page |

## az-post-exploitation/az-stream-analytics-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-stream-analytics-post-exploitation.md#az---stream-analytics-post-exploitation` | Az - Stream Analytics Post Exploitation |  | STRUCTURAL | post-exploitation page title |
| `az-post-exploitation/az-stream-analytics-post-exploitation.md#stream-analytics` | Stream Analytics |  | EXCLUDED | Introductory section. |
| `az-post-exploitation/az-stream-analytics-post-exploitation.md#sample-private-input-events` | Sample private input events | Microsoft.StreamAnalytics/streamingjobs/inputs/OperationResults/read,Microsoft.StreamAnalytics/streamingjobs/inputs/Sample/action | EXCLUDED | Data read. |
| `az-post-exploitation/az-stream-analytics-post-exploitation.md#redirect-a-running-jobs-output-sink-with-stop--outputswrite--start` | Redirect a running job's output sink with `Stop` + `outputs/Write` + `Start` | Microsoft.StreamAnalytics/streamingjobs/Start/action,Microsoft.StreamAnalytics/streamingjobs/Stop/action,Microsoft.StreamAnalytics/streamingjobs/outputs/Write | EXCLUDED | Data exfiltration; no identity gain. |
| `az-post-exploitation/az-stream-analytics-post-exploitation.md#full-job-rewrite--managed-identity-attach-with-streamingjobswrite` | Full-job rewrite + managed-identity attach with `streamingjobs/Write` | Microsoft.ManagedIdentity/userAssignedIdentities/*/assign/action,Microsoft.StreamAnalytics/*,Microsoft.StreamAnalytics/streamingjobs/Write | EXCLUDED | Confused-deputy use of the job identity: Stream Analytics queries and outputs only read and write data through configured connectors, with no token disclosure or attacker-chosen code execution. Data access only. |
| `az-post-exploitation/az-stream-analytics-post-exploitation.md#msi-backed-confused-deputy-source-read-with-inputswrite` | MSI-backed confused-deputy source read with `inputs/Write` | Microsoft.StreamAnalytics/streamingjobs/inputs/Write | EXCLUDED | Confused-deputy data read through the job's managed identity; no identity or token is gained. |
| `az-post-exploitation/az-stream-analytics-post-exploitation.md#azure-ml-udf-endpoint-repoint-with-functionswrite` | Azure ML UDF endpoint repoint with `functions/Write` | Microsoft.StreamAnalytics/streamingjobs/functions/Write | EXCLUDED | Data exfiltration and request relay to an attacker endpoint; JavaScript and C# UDFs are sandboxed and expose no identity token. |
| `az-post-exploitation/az-stream-analytics-post-exploitation.md#job-less-egress--credential-validation-proxy-with-locationssampleinputaction` | Job-less egress / credential-validation proxy with `locations/SampleInput/action` | Microsoft.StreamAnalytics/locations/SampleInput/action | EXCLUDED | Service-side proxy using credentials the caller supplies; no new identity. |

## az-privilege-escalation/az-synapse-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-synapse-privesc.md#az---synapse-privesc` | Az - Synapse Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-synapse-privesc.md#azure-synapse-analytics` | Azure Synapse Analytics |  | EXCLUDED | Introductory section. |
| `az-privilege-escalation/az-synapse-privesc.md#replace-the-workspace-microsoft-entra-administrator` | Replace the workspace Microsoft Entra administrator | Microsoft.Synapse/workspaces/administrators/write,Microsoft.Synapse/workspaces/sqlAdministrators/write | MAPPED | `azure-synapse-entra-admin-write` |
| `az-privilege-escalation/az-synapse-privesc.md#bash--azure-cli` | Bash / Azure CLI |  | SUBSECTION | of #replace-the-workspace-microsoft-entra-administrator: MAPPED azure-synapse-entra-admin-write |
| `az-privilege-escalation/az-synapse-privesc.md#powershell` | PowerShell |  | STRUCTURAL | section/how-to heading; no technique |
| `az-privilege-escalation/az-synapse-privesc.md#permission-boundaries` | Permission boundaries |  | STRUCTURAL | section/how-to heading; no technique |
| `az-privilege-escalation/az-synapse-privesc.md#open-the-workspace-firewall-to-reach-sql--dev-endpoints` | Open the workspace firewall to reach SQL / dev endpoints | Microsoft.Synapse/workspaces/firewallRules/write,Microsoft.Synapse/workspaces/replaceAllIpFirewallRules/action | EXCLUDED | Network reachability only; no new identity. |
| `az-privilege-escalation/az-synapse-privesc.md#rogue-self-hosted-integration-runtime-node-synapse` | Rogue self-hosted Integration Runtime node (Synapse) | Microsoft.Synapse/workspaces/integrationRuntimes/listAuthKeys/action | EXCLUDED | Strict principal-boundary audit: The credential_stored_in_scope selector has no exact usable credential and identified target-principal evidence enforcement for this technique; a secret read or arbitrary configuration change alone is not an established principal escalation. |
| `az-privilege-escalation/az-synapse-privesc.md#spark-pool-poisoning-via-workspacesbigdatapoolswrite` | Spark pool poisoning via `workspaces/bigDataPools/write` | Microsoft.Synapse/workspaces/bigDataPools/write | EXCLUDED | NEEDS SCHEMA: Spark pool write alone does not establish a later run of attacker code as the exact workspace identity or successful access to its token/new permission. |
| `az-privilege-escalation/az-synapse-privesc.md#grant-the-workspace-msi-sql-control-with-managedidentitysqlcontrolsettingswrite` | Grant the workspace MSI SQL control with `managedIdentitySqlControlSettings/write` | Microsoft.Synapse/workspaces/managedIdentitySqlControlSettings/write | EXCLUDED | Enabler only: grants the workspace identity SQL control, which the source can use only through a separate execution primitive as that identity (see azure-synapse-bigdatapools-write-spark-poisoning). |
| `az-privilege-escalation/az-synapse-privesc.md#git-repo-poisoning-via-workspaceswrite` | Git-repo poisoning via `workspaces/write` | Microsoft.Synapse/workspaces/write | EXCLUDED | Supply-chain change that needs another principal to publish or run the poisoned artifacts; not derivable. |
| `az-privilege-escalation/az-synapse-privesc.md#references` | References |  | STRUCTURAL | section/how-to heading; no technique |

## az-privilege-escalation/az-video-indexer-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-video-indexer-privesc.md#az---azure-ai-video-indexer-privesc` | Az - Azure AI Video Indexer Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-video-indexer-privesc.md#azure-ai-video-indexer` | Azure AI Video Indexer |  | EXCLUDED | Introductory section. |
| `az-privilege-escalation/az-video-indexer-privesc.md#account-access-token--private-media-readwrite` | Account access token — private media read/write | Microsoft.VideoIndexer/accounts/generateAccessToken/action | EXCLUDED | NEEDS SCHEMA: Exact Video Indexer account subject, token role, and newly permitted media action must be verified. |
| `az-privilege-escalation/az-video-indexer-privesc.md#restricted-viewer-access-token--private-insights` | Restricted-viewer access token — private insights | Microsoft.VideoIndexer/accounts/generateRestrictedViewerAccessToken/action | EXCLUDED | NEEDS SCHEMA: Exact Video Indexer token subject/role and newly permitted insight action must be verified. |
| `az-privilege-escalation/az-video-indexer-privesc.md#permission-boundary` | Permission boundary |  | EXCLUDED | Background section. |
| `az-privilege-escalation/az-video-indexer-privesc.md#arc-extension-token-operations` | Arc extension token operations | Microsoft.VideoIndexer/accounts/generateExtensionAccessToken/action,Microsoft.VideoIndexer/accounts/generateExtensionRestrictedViewerAccessToken/action | EXCLUDED | NEEDS SCHEMA: Exact Arc extension token subject/role and newly permitted action must be verified. |
| `az-privilege-escalation/az-video-indexer-privesc.md#references` | References |  | STRUCTURAL | section/how-to heading; no technique |

## az-privilege-escalation/az-virtual-desktop-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-virtual-desktop-privesc.md#az---virtual-desktop-privesc` | Az - Virtual Desktop Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-virtual-desktop-privesc.md#virtual-desktop` | Virtual Desktop |  | EXCLUDED | Introductory section. |
| `az-privilege-escalation/az-virtual-desktop-privesc.md#azure-virtual-desktop-privesc` | Azure Virtual Desktop Privesc |  | STRUCTURAL | section grouping heading; techniques are its subsections |
| `az-privilege-escalation/az-virtual-desktop-privesc.md#microsoftdesktopvirtualizationhostpoolsretrieveregistrationtokenaction` | `Microsoft.DesktopVirtualization/hostPools/retrieveRegistrationToken/action` | Microsoft.DesktopVirtualization/hostPools/retrieveRegistrationToken/action | EXCLUDED | NEEDS SCHEMA: Exact compliant session host, named session principal, observed credential/session capture, and newly authorized action must be verified. |
| `az-privilege-escalation/az-virtual-desktop-privesc.md#microsoftauthorizationroleassignmentsread-microsoftauthorizationroleassignmentswrite` | Microsoft.Authorization/roleAssignments/read, Microsoft.Authorization/roleAssignments/write | Microsoft.Authorization/roleAssignments/read,Microsoft.Authorization/roleAssignments/write | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-authorization-privesc.md#microsoftauthorizationroleassignmentswrite` |
| `az-privilege-escalation/az-virtual-desktop-privesc.md#references` | References |  | STRUCTURAL | references/enumeration |

## az-privilege-escalation/az-virtual-machines-and-network-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#az---virtual-machines--network-privesc` | Az - Virtual Machines & Network Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#virtual-machines--network` | Virtual Machines & Network |  | EXCLUDED | Introductory section. |
| `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#vms--network` | VMS & Network |  | STRUCTURAL | section grouping heading; techniques are its subsections |
| `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputevirtualmachinesextensionswrite` | **`Microsoft.Compute/virtualMachines/extensions/write`** | Microsoft.Compute/virtualMachines/extensions/write | MAPPED | `azure-vm-extensions-write` |
| `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#rogue-salt-master-via-salt-minion` | Rogue Salt Master via Salt Minion |  | SUBSECTION | of #microsoftcomputevirtualmachinesextensionswrite: MAPPED azure-vm-extensions-write |
| `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputegallerieswrite-microsoftcomputegalleriesapplicationswrite-microsoftcomputegalleriesapplicationsversionswrite-microsoftcomputevirtualmachineswrite` | `Microsoft.Compute/galleries/write`, `Microsoft.Compute/galleries/applications/write`, `Microsoft.Compute/galleries/applications/versions/write`, `Microsoft.Compute/virtualMachines/write` | Microsoft.Compute/galleries/applications/versions/write,Microsoft.Compute/galleries/applications/write,Microsoft.Compute/galleries/write,Microsoft.Compute/virtualMachines/write | MAPPED | `azure-vm-gallery-application-install` |
| `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputevirtualmachinesruncommandaction` | `Microsoft.Compute/virtualMachines/runCommand/action` | Microsoft.Compute/virtualMachines/runCommand/action | MAPPED | `azure-vm-runcommand-action` `azure-vmss-vm-runcommand-action` |
| `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputevirtualmachinesruncommandswrite` | `Microsoft.Compute/virtualMachines/runCommands/write` | Microsoft.Compute/virtualMachines/runCommands/write,Microsoft.HybridCompute/machines/runcommands/write | MAPPED | `azure-vm-managed-runcommands-write` `azure-vmss-vm-managed-runcommands-write` `azure-arc-machine-runcommands-write` |
| `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputevirtualmachinesloginaction` | `Microsoft.Compute/virtualMachines/login/action` | Microsoft.Compute/virtualMachines/login/action | EXCLUDED | NEEDS SCHEMA: Entra VM login assignment does not prove installed login extension, reachable VM, Conditional Access acceptance, successful guest session, and exact MI token/new action. |
| `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputevirtualmachinesloginasadminaction` | `Microsoft.Compute/virtualMachines/loginAsAdmin/action` | Microsoft.Compute/virtualMachines/loginAsAdmin/action | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputevirtualmachinesloginaction` |
| `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftresourcesdeploymentswrite-microsoftnetworkvirtualnetworkswrite-microsoftnetworknetworksecuritygroupswrite-microsoftnetworknetworksecuritygroupsjoinaction-microsoftnetworkpublicipaddresseswrite-microsoftnetworkpublicipaddressesjoinaction-microsoftnetworknetworkinterfaceswrite-microsoftcomputevirtualmachineswrite-microsoftnetworkvirtualnetworkssubnetsjoinaction-microsoftnetworknetworkinterfacesjoinaction-microsoftmanagedidentityuserassignedidentitiesassignaction` | `Microsoft.Resources/deployments/write`, `Microsoft.Network/virtualNetworks/write`, `Microsoft.Network/networkSecurityGroups/write`, `Microsoft.Network/networkSecurityGroups/join/action`, `Microsoft.Network/publicIPAddresses/write`, `Microsoft.Network/publicIPAddresses/join/action`, `Microsoft.Network/networkInterfaces/write`, `Microsoft.Compute/virtualMachines/write`, `Microsoft.Network/virtualNetworks/subnets/join/action`, `Microsoft.Network/networkInterfaces/join/action`, `Microsoft.ManagedIdentity/userAssignedIdentities/assign/action` | Microsoft.Compute/virtualMachines/write,Microsoft.ManagedIdentity/userAssignedIdentities/assign/action,Microsoft.Network/networkInterfaces/join/action,Microsoft.Network/networkInterfaces/write,Microsoft.Network/networkSecurityGroups/join/action,Microsoft.Network/networkSecurityGroups/write,Microsoft.Network/publicIPAddresses/join/action,Microsoft.Network/publicIPAddresses/write,Microsoft.Network/virtualNetworks/subnets/join/action,Microsoft.Network/virtualNetworks/write,Microsoft.Resources/deployments/write | MAPPED | `azure-vm-create-with-user-assigned-identity` |
| `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputevirtualmachineswrite-microsoftmanagedidentityuserassignedidentitiesassignaction` | `Microsoft.Compute/virtualMachines/write`, `Microsoft.ManagedIdentity/userAssignedIdentities/assign/action` | Microsoft.Compute/virtualMachines/write,Microsoft.ManagedIdentity/userAssignedIdentities/assign/action | MAPPED | `azure-vm-assign-user-assigned-identity-existing` `azure-vm-assign-user-assigned-identity-indirect-exec` |
| `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputevirtualmachinesread-microsoftcomputevirtualmachineswrite-microsoftcomputevirtualmachinesextensionsread-microsoftcomputevirtualmachinesextensionswrite` | Microsoft.Compute/virtualMachines/read, Microsoft.Compute/virtualMachines/write, Microsoft.Compute/virtualMachines/extensions/read, Microsoft.Compute/virtualMachines/extensions/write | Microsoft.Compute/virtualMachines/extensions/read,Microsoft.Compute/virtualMachines/extensions/write,Microsoft.Compute/virtualMachines/read,Microsoft.Compute/virtualMachines/write | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputevirtualmachinesextensionswrite` |
| `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftserialconsoleserialportsconnectaction` | `Microsoft.SerialConsole/serialPorts/connect/action` | Microsoft.SerialConsole/serialPorts/connect/action | EXCLUDED | NEEDS SCHEMA: Restart and serial-console access do not prove a usable guest recovery/login route, exact VM code execution, or acquisition of its managed-identity token/new action. |
| `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputevirtualmachineswrite-os-disk-swap` | `Microsoft.Compute/virtualMachines/write` (OS-disk swap) | Microsoft.Compute/virtualMachines/write | MAPPED | `azure-vm-os-disk-swap` |
| `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputevirtualmachinescalesetswrite-scale-set-model-tampering` | `Microsoft.Compute/virtualMachineScaleSets/write` (scale-set model tampering) | Microsoft.Compute/virtualMachineScaleSets/write | MAPPED | `azure-vmss-model-write` |
| `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputevirtualmachinesread-microsoftcomputevirtualmachineswrite-microsoftcomputedisksread-microsoftcomputediskswrite` | `Microsoft.Compute/virtualMachines/read`, `Microsoft.Compute/virtualMachines/write`, `Microsoft.Compute/disks/read`, `Microsoft.Compute/disks/write` | Microsoft.Compute/disks/read,Microsoft.Compute/disks/write,Microsoft.Compute/virtualMachines/read,Microsoft.Compute/virtualMachines/write | EXCLUDED | Offline data access to disk contents; any credential found is content-dependent (Exposure). No identity is obtained by the operation itself. |
| `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#managed-disk-snapshot-and-restore-point-sas-exfiltration` | Managed-disk, snapshot, and restore-point SAS exfiltration | Microsoft.Compute/disks/beginGetAccess/action,Microsoft.Compute/snapshots/beginGetAccess/action | EXCLUDED | Data exfiltration of VHD contents; no identity gain. |
| `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftnetworkvpnserverconfigurationslistallradiusserverssecretsaction` | Microsoft.Network/vpnServerConfigurations/listAllRadiusServersSecrets/action | Microsoft.Network/vpnServerConfigurations/listAllRadiusServersSecrets/action | EXCLUDED | Network trust secret (RADIUS shared secret); network pivot without a new Azure identity. |
| `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftnetworkvirtualnetworkgatewayslistallradiusserverssecretsaction` | `microsoft.network/virtualnetworkgateways/listAllRadiusServersSecrets/action` | Microsoft.Network/virtualNetworkGateways/listAllRadiusServersSecrets/action | EXCLUDED | Network trust secret; network pivot without a new Azure identity. |
| `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftnetworkconnectionssharedkeyaction-microsoftnetworkconnectionssharedkeyread` | `Microsoft.Network/connections/sharedkey/action`, `Microsoft.Network/connections/sharedKey/read` | Microsoft.Network/connections/sharedKey/read,Microsoft.Network/connections/sharedkey/action | EXCLUDED | VPN pre-shared key disclosure; network pivot without a new Azure identity. |
| `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#point-to-site-vpn-root-certificate-injection-durable-vnet-access` | Point-to-Site VPN root-certificate injection (durable VNet access) | Microsoft.Network/*,Microsoft.Network/virtualNetworkGateways/write,Microsoft.Network/vpnServerConfigurations/write | EXCLUDED | Network access and persistence only; no new identity. |
| `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#references` | References |  | STRUCTURAL | references/enumeration |

## az-privilege-escalation/az-vm-code-execution-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-vm-code-execution-privesc.md#az---vm-control-plane-code-execution-privesc` | Az - VM control-plane code execution Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-vm-code-execution-privesc.md#virtual-machines` | Virtual Machines |  | EXCLUDED | Introductory section. |
| `az-privilege-escalation/az-vm-code-execution-privesc.md#code-execution-in-vms` | Code Execution in VMs |  | STRUCTURAL | section grouping heading; techniques are its subsections |
| `az-privilege-escalation/az-vm-code-execution-privesc.md#vm-extensions` | VM Extensions |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputevirtualmachinesextensionswrite` |
| `az-privilege-escalation/az-vm-code-execution-privesc.md#relevant-vm-extensions` | Relevant VM extensions |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputevirtualmachinesextensionswrite` |
| `az-privilege-escalation/az-vm-code-execution-privesc.md#vm-applications` | VM Applications |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputegallerieswrite-microsoftcomputegalleriesapplicationswrite-microsoftcomputegalleriesapplicationsversionswrite-microsoftcomputevirtualmachineswrite` |
| `az-privilege-escalation/az-vm-code-execution-privesc.md#user-data` | User data |  | EXCLUDED | User data is not executed by the platform; only guest software that reads it could act on it, which is not derivable. |
| `az-privilege-escalation/az-vm-code-execution-privesc.md#custom-data` | Custom data |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftresourcesdeploymentswrite-microsoftnetworkvirtualnetworkswrite-microsoftnetworknetworksecuritygroupswrite-microsoftnetworknetworksecuritygroupsjoinaction-microsoftnetworkpublicipaddresseswrite-microsoftnetworkpublicipaddressesjoinaction-microsoftnetworknetworkinterfaceswrite-microsoftcomputevirtualmachineswrite-microsoftnetworkvirtualnetworkssubnetsjoinaction-microsoftnetworknetworkinterfacesjoinaction-microsoftmanagedidentityuserassignedidentitiesassignaction`, `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#reimage--redeploy-to-re-execute-poisoned-customdata` |
| `az-privilege-escalation/az-vm-code-execution-privesc.md#run-command` | **Run Command** |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputevirtualmachinesruncommandaction` |
| `az-privilege-escalation/az-vm-code-execution-privesc.md#references` | References |  | STRUCTURAL | references/enumeration |

## az-privilege-escalation/az-vm-managed-identity-token-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-vm-managed-identity-token-privesc.md#az---vm-managed-identity-token-privesc` | Az - VM managed identity token Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-vm-managed-identity-token-privesc.md#virtual-machines` | Virtual Machines |  | EXCLUDED | Introductory section. |
| `az-privilege-escalation/az-vm-managed-identity-token-privesc.md#managed-identity-access-from-inside-the-vm` | Managed Identity Access From Inside the VM |  | EXCLUDED | Background section. IMDS token issuance is the outcome of the VM code-execution entries. |
| `az-privilege-escalation/az-vm-managed-identity-token-privesc.md#references` | References |  | STRUCTURAL | references/enumeration |

## az-privilege-escalation/az-vmware-solution-avs-privesc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-vmware-solution-avs-privesc.md#az---vmware-solution-avs-privesc` | Az - VMware Solution (AVS) Privesc |  | STRUCTURAL | page title |
| `az-privilege-escalation/az-vmware-solution-avs-privesc.md#azure-vmware-solution` | Azure VMware Solution |  | EXCLUDED | Introductory section. |
| `az-privilege-escalation/az-vmware-solution-avs-privesc.md#cloudadmin--nsx-t-credential-disclosure-listadmincredentials` | CloudAdmin & NSX-T credential disclosure (`listAdminCredentials`) | Microsoft.AVS/privateClouds/listAdminCredentials/action,Microsoft.AVS/privateClouds/read | MAPPED | `azure-avs-list-vcenter-cloudadmin-external-principal`, `azure-avs-list-nsxt-admin-external-principal` require exact reviewed subjects, usable credentials, prior denial, and newly allowed service actions. The historical resource-proxy ID remains excluded. |
| `az-privilege-escalation/az-vmware-solution-avs-privesc.md#run-command-rce-without-reading-credentials-scriptexecutionswrite` | Run Command RCE without reading credentials (`scriptExecutions/write`) | Microsoft.AVS/privateClouds/scriptExecutions/write,Microsoft.AVS/privateClouds/scriptPackages/read,Microsoft.AVS/privateClouds/scriptPackages/scriptCmdlets/read | MAPPED | `azure-avs-run-command-vcenter-grant-external-principal` requires exact successful cmdlet, target subject, identity grant, and new authority. The historical resource-proxy ID remains excluded. |
| `az-privilege-escalation/az-vmware-solution-avs-privesc.md#references` | References |  | STRUCTURAL | references/enumeration |

## README.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `README.md` | (page) |  | STRUCTURAL | page reviewed: explanatory / tooling / enumeration |
| `README.md#azure-pentesting` | Azure Pentesting |  | STRUCTURAL | title/reference/intro heading |
| `README.md#basic-information` | Basic Information |  | STRUCTURAL | title/reference/intro heading |
| `README.md#azure-pentesterred-team-methodology` | Azure Pentester/Red Team Methodology |  | EXCLUDED | explanatory / tooling / enumeration |
| `README.md#external-enum--initial-access` | External enum & Initial Access |  | SUBSECTION | of #azure-pentesterred-team-methodology: EXCLUDED: explanatory / tooling / enumeration |
| `README.md#azure--entra-id-tooling` | Azure & Entra ID tooling |  | SUBSECTION | of #azure-pentesterred-team-methodology: EXCLUDED: explanatory / tooling / enumeration |
| `README.md#bypass-access-policies` | Bypass Access Policies |  | SUBSECTION | of #azure-pentesterred-team-methodology: EXCLUDED: explanatory / tooling / enumeration |
| `README.md#whoami` | Whoami |  | SUBSECTION | of #azure-pentesterred-team-methodology: EXCLUDED: explanatory / tooling / enumeration |
| `README.md#entra-id-enumeration--privesc` | Entra ID Enumeration & Privesc |  | SUBSECTION | of #azure-pentesterred-team-methodology: EXCLUDED: explanatory / tooling / enumeration |
| `README.md#azure-enumeration` | Azure Enumeration |  | SUBSECTION | of #azure-pentesterred-team-methodology: EXCLUDED: explanatory / tooling / enumeration |
| `README.md#privilege-escalation-post-exploitation--persistence` | Privilege Escalation, Post-Exploitation & Persistence |  | SUBSECTION | of #azure-pentesterred-team-methodology: EXCLUDED: explanatory / tooling / enumeration |
| `README.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-basic-information/README.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-basic-information/README.md` | (page) |  | STRUCTURAL | page reviewed: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/README.md#az---basic-information` | Az - Basic Information |  | STRUCTURAL | title/reference/intro heading |
| `az-basic-information/README.md#organization-hierarchy` | Organization Hierarchy |  | EXCLUDED | explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/README.md#management-groups` | Management Groups |  | SUBSECTION | of #organization-hierarchy: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/README.md#azure-subscriptions` | Azure Subscriptions |  | SUBSECTION | of #organization-hierarchy: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/README.md#resource-groups` | Resource Groups |  | SUBSECTION | of #organization-hierarchy: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/README.md#azure-resource-ids` | Azure Resource IDs |  | SUBSECTION | of #organization-hierarchy: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/README.md#azure-vs-entra-id-vs-azure-ad-domain-services` | Azure vs Entra ID vs Azure AD Domain Services |  | EXCLUDED | explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/README.md#azure` | Azure |  | SUBSECTION | of #azure-vs-entra-id-vs-azure-ad-domain-services: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/README.md#entra-id-formerly-azure-active-directory` | Entra ID (formerly Azure Active Directory) |  | SUBSECTION | of #azure-vs-entra-id-vs-azure-ad-domain-services: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/README.md#entra-domain-services-formerly-azure-ad-ds` | Entra Domain Services (formerly Azure AD DS) |  | SUBSECTION | of #azure-vs-entra-id-vs-azure-ad-domain-services: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/README.md#entra-id-principals` | Entra ID Principals |  | EXCLUDED | explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/README.md#users` | Users |  | SUBSECTION | of #entra-id-principals: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/README.md#members--guests-default-permissions` | Members & Guests Default Permissions |  | SUBSECTION | of #entra-id-principals: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/README.md#users-default-configurable-permissions` | Users Default Configurable Permissions |  | SUBSECTION | of #entra-id-principals: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/README.md#groups` | **Groups** |  | SUBSECTION | of #entra-id-principals: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/README.md#service-principals` | **Service Principals** |  | SUBSECTION | of #entra-id-principals: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/README.md#app-registrations` | App Registrations |  | SUBSECTION | of #entra-id-principals: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/README.md#key-components` | Key Components: |  | STRUCTURAL | title/reference/intro heading |
| `az-basic-information/README.md#default-consent-permissions` | Default Consent Permissions |  | SUBSECTION | of #entra-id-principals: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/README.md#managed-identity-metadata` | **Managed Identity (Metadata)** |  | SUBSECTION | of #entra-id-principals: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/README.md#enterprise-applications` | Enterprise Applications |  | SUBSECTION | of #entra-id-principals: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/README.md#administrative-units` | Administrative Units |  | SUBSECTION | of #entra-id-principals: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/README.md#entra-id-roles--permissions` | Entra ID Roles & Permissions |  | SUBSECTION | of #entra-id-principals: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/README.md#azure-roles--permissions` | Azure Roles & Permissions |  | EXCLUDED | explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/README.md#built-in-roles` | Built-In roles |  | SUBSECTION | of #azure-roles--permissions: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/README.md#custom-roles` | Custom Roles |  | SUBSECTION | of #azure-roles--permissions: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/README.md#permissions-order` | Permissions order |  | SUBSECTION | of #azure-roles--permissions: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/README.md#global-administrator` | Global Administrator |  | EXCLUDED | Already modelled as azure-authorization-elevateaccess-global-admin in catalog/azure/authorization.yaml; not duplicated. |
| `az-basic-information/README.md#assignments-conditions--mfa` | Assignments Conditions & MFA |  | EXCLUDED | explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/README.md#deny-assignments` | Deny Assignments |  | EXCLUDED | explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/README.md#azure-policies` | Azure Policies |  | EXCLUDED | explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/README.md#key-concepts` | **Key Concepts** |  | SUBSECTION | of #azure-policies: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/README.md#permissions-inheritance` | Permissions Inheritance |  | EXCLUDED | explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/README.md#azure-rbac-vs-abac` | Azure RBAC vs ABAC |  | EXCLUDED | explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/README.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-basic-information/az-federation-abuse.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-basic-information/az-federation-abuse.md` | (page) |  | STRUCTURAL | page reviewed: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/az-federation-abuse.md#azure--federation-abuse-github-actions-oidc--workload-identity` | Azure – Federation Abuse (GitHub Actions OIDC / Workload Identity) |  | STRUCTURAL | title/reference/intro heading |
| `az-basic-information/az-federation-abuse.md#overview` | Overview |  | STRUCTURAL | title/reference/intro heading |
| `az-basic-information/az-federation-abuse.md#github-id-token-quick-poc` | GitHub ID token quick PoC |  | EXCLUDED | explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/az-federation-abuse.md#azure-setup-workload-identity-federation` | Azure setup (Workload Identity Federation) |  | EXCLUDED | explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/az-federation-abuse.md#github-oidc-subject-sub-anatomy-and-customization` | GitHub OIDC subject (sub) anatomy and customization |  | EXCLUDED | explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/az-federation-abuse.md#scoping-and-risks-of-fic-subject-types` | Scoping and risks of FIC subject types |  | EXCLUDED | The source is an external CI identity, not a tenant principal; FIC creation by tenant principals is covered by the credential-update entries. |
| `az-basic-information/az-federation-abuse.md#reusable-workflows-and-job_workflow_ref-scoping` | Reusable workflows and job_workflow_ref scoping |  | EXCLUDED | explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/az-federation-abuse.md#code-execution-vectors-that-bypass-job_workflow_ref-protections` | Code execution vectors that bypass job_workflow_ref protections |  | EXCLUDED | explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/az-federation-abuse.md#terraform-plan-as-an-execution-primitive-in-prs` | Terraform plan as an execution primitive in PRs |  | EXCLUDED | explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/az-federation-abuse.md#manual-testing-tips` | Manual testing tips |  | EXCLUDED | explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/az-federation-abuse.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-basic-information/az-tokens-and-public-applications.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-basic-information/az-tokens-and-public-applications.md` | (page) |  | STRUCTURAL | page reviewed: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/az-tokens-and-public-applications.md#az---tokens--public-applications` | Az - Tokens & Public Applications |  | STRUCTURAL | title/reference/intro heading |
| `az-basic-information/az-tokens-and-public-applications.md#basic-information` | Basic Information |  | STRUCTURAL | title/reference/intro heading |
| `az-basic-information/az-tokens-and-public-applications.md#oauth` | OAuth |  | EXCLUDED | explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/az-tokens-and-public-applications.md#ropc--password-grant` | ROPC / Password Grant |  | EXCLUDED | explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/az-tokens-and-public-applications.md#entra-id-sign-in-log-bypass-classes` | Entra ID Sign-In Log Bypass Classes |  | EXCLUDED | explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/az-tokens-and-public-applications.md#1-foreign-tenant-endpoint-for-stealth-password-validation` | 1. Foreign-tenant endpoint for stealth password validation |  | SUBSECTION | of #entra-id-sign-in-log-bypass-classes: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/az-tokens-and-public-applications.md#2-force-a-post-password-failure` | 2. Force a post-password failure |  | SUBSECTION | of #entra-id-sign-in-log-bypass-classes: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/az-tokens-and-public-applications.md#3-trigger-logging-failure-with-oversized-but-valid-values` | 3. Trigger logging failure with oversized-but-valid values |  | SUBSECTION | of #entra-id-sign-in-log-bypass-classes: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/az-tokens-and-public-applications.md#hunting--defensive-note` | Hunting / defensive note |  | SUBSECTION | of #entra-id-sign-in-log-bypass-classes: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/az-tokens-and-public-applications.md#authentication-tokens` | Authentication Tokens |  | EXCLUDED | explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/az-tokens-and-public-applications.md#access-tokens-aud` | Access Tokens "aud" |  | SUBSECTION | of #authentication-tokens: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/az-tokens-and-public-applications.md#access-tokens-scopes-scp` | Access Tokens Scopes "scp" |  | SUBSECTION | of #authentication-tokens: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/az-tokens-and-public-applications.md#get-refresh--access-token-example` | Get refresh & access token example |  | SUBSECTION | of #authentication-tokens: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/az-tokens-and-public-applications.md#other-access-token-fields` | Other access token fields |  | SUBSECTION | of #authentication-tokens: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/az-tokens-and-public-applications.md#oauth-token-exchange-instrumentation-with-tats` | OAuth token exchange instrumentation with TATS |  | EXCLUDED | explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/az-tokens-and-public-applications.md#collection-workflow` | Collection workflow |  | SUBSECTION | of #oauth-token-exchange-instrumentation-with-tats: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/az-tokens-and-public-applications.md#audiencehost-mismatch-triage` | Audience/host mismatch triage |  | SUBSECTION | of #oauth-token-exchange-instrumentation-with-tats: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/az-tokens-and-public-applications.md#pre-mfa-tokens-and-downstream-conditional-access-gaps` | Pre-MFA tokens and downstream Conditional Access gaps |  | SUBSECTION | of #oauth-token-exchange-instrumentation-with-tats: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/az-tokens-and-public-applications.md#foci-tokens-privilege-escalation` | FOCI Tokens Privilege Escalation |  | EXCLUDED | explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/az-tokens-and-public-applications.md#get-different-scope` | Get different scope |  | SUBSECTION | of #foci-tokens-privilege-escalation: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/az-tokens-and-public-applications.md#get-different-client-and-scopes` | Get different client and scopes |  | SUBSECTION | of #foci-tokens-privilege-escalation: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/az-tokens-and-public-applications.md#naa--broci-nested-app-authentication--broker-client-injection` | NAA / BroCI (Nested App Authentication / Broker Client Injection) |  | EXCLUDED | Strict principal-boundary audit: The declared target is a bounded authority rather than an identified target principal or an explicit grant of extra permissions to the caller. |
| `az-basic-information/az-tokens-and-public-applications.md#goal-and-purpose` | Goal and purpose |  | SUBSECTION | of #naa--broci-nested-app-authentication--broker-client-injection: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/az-tokens-and-public-applications.md#mental-model` | Mental model |  | SUBSECTION | of #naa--broci-nested-app-authentication--broker-client-injection: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/az-tokens-and-public-applications.md#where-to-find-a-broci-valid-refresh-token` | Where to find a BroCI-valid refresh token |  | SUBSECTION | of #naa--broci-nested-app-authentication--broker-client-injection: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/az-tokens-and-public-applications.md#common-errors` | Common errors |  | SUBSECTION | of #naa--broci-nested-app-authentication--broker-client-injection: EXCLUDED: explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/az-tokens-and-public-applications.md#where-to-find-tokens` | Where to find tokens |  | EXCLUDED | explanatory / token mechanics (FOCI, NAA, ROPC reuse the same principal) |
| `az-basic-information/az-tokens-and-public-applications.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-cross-tenant-and-cross-subscription-attacks/README.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-cross-tenant-and-cross-subscription-attacks/README.md` | (page) |  | STRUCTURAL | page reviewed: cross-tenant: phishing/consent, trust-setting bypass, out-of-graph source tenant, or data-plane sharing |
| `az-cross-tenant-and-cross-subscription-attacks/README.md#az---cross-tenant--cross-subscription-attacks` | Az - Cross-Tenant & Cross-Subscription Attacks |  | STRUCTURAL | title/reference/intro heading |
| `az-cross-tenant-and-cross-subscription-attacks/README.md#the-authorization-model` | The authorization model |  | EXCLUDED | cross-tenant: phishing/consent, trust-setting bypass, out-of-graph source tenant, or data-plane sharing |
| `az-cross-tenant-and-cross-subscription-attacks/README.md#attack-families` | Attack families |  | EXCLUDED | cross-tenant: phishing/consent, trust-setting bypass, out-of-graph source tenant, or data-plane sharing |
| `az-cross-tenant-and-cross-subscription-attacks/README.md#initial-reconnaissance` | Initial reconnaissance |  | EXCLUDED | cross-tenant: phishing/consent, trust-setting bypass, out-of-graph source tenant, or data-plane sharing |
| `az-cross-tenant-and-cross-subscription-attacks/README.md#common-end-to-end-chains` | Common end-to-end chains |  | EXCLUDED | cross-tenant: phishing/consent, trust-setting bypass, out-of-graph source tenant, or data-plane sharing |
| `az-cross-tenant-and-cross-subscription-attacks/README.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-cross-tenant-and-cross-subscription-attacks/cross-subscription-rbac-and-management-group-attacks.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-cross-tenant-and-cross-subscription-attacks/cross-subscription-rbac-and-management-group-attacks.md#the-role-assignment-primitive` | The role-assignment primitive |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-authorization-privesc.md#microsoftauthorizationroleassignmentswrite` |
| `az-cross-tenant-and-cross-subscription-attacks/cross-subscription-rbac-and-management-group-attacks.md#global-administrator--root-scope-takeover-elevateaccess` | Global Administrator → root-scope takeover (`/elevateAccess`) |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-authorization-privesc.md#microsoftauthorizationelevateaccessaction` |
| `az-cross-tenant-and-cross-subscription-attacks/cross-subscription-rbac-and-management-group-attacks.md#management-group-scope-one-assignment-many-subscriptions` | Management-group scope: one assignment, many subscriptions |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-authorization-privesc.md#microsoftauthorizationroleassignmentswrite` |
| `az-cross-tenant-and-cross-subscription-attacks/cross-subscription-rbac-and-management-group-attacks.md#azure-lighthouse-durable-cross-tenant-control-plane-access` | Azure Lighthouse: durable cross-tenant control-plane access |  | EXCLUDED | Onboarding needs roleAssignments/write at the scope (azure-authorization-roleassignments-write); the result is cross-tenant persistence for principals the attacker already controls. |
| `az-cross-tenant-and-cross-subscription-attacks/cross-subscription-rbac-and-management-group-attacks.md#subscription-to-tenant-transfer-re-homing` | Subscription-to-tenant transfer (re-homing) |  | EXCLUDED | Needs a directly assigned subscription Owner (already scope owner); RBAC is wiped on transfer, so the effect is resource/data theft, not a new principal. |
| `az-cross-tenant-and-cross-subscription-attacks/cross-subscription-rbac-and-management-group-attacks.md#management-group-hierarchy-settings-tamper-default-mg-hijack` | Management-group hierarchy-settings tamper (default-MG hijack) |  | EXCLUDED | Affects only subscriptions created in the future under an MG the attacker already controls; no existing principal or scope is gained at analysis time (persistence). |
| `az-cross-tenant-and-cross-subscription-attacks/cross-subscription-rbac-and-management-group-attacks.md` | Az - Cross-Subscription RBAC & Management Group Attacks |  | EXCLUDED | page reviewed: cross-subscription RBAC primitives; rows below |

## az-cross-tenant-and-cross-subscription-attacks/cross-tenant-identity-attacks.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-cross-tenant-and-cross-subscription-attacks/cross-tenant-identity-attacks.md` | (page) |  | STRUCTURAL | page reviewed: cross-tenant: phishing/consent, trust-setting bypass, out-of-graph source tenant, or data-plane sharing |
| `az-cross-tenant-and-cross-subscription-attacks/cross-tenant-identity-attacks.md#az---cross-tenant-identity-attacks` | Az - Cross-Tenant Identity Attacks |  | STRUCTURAL | title/reference/intro heading |
| `az-cross-tenant-and-cross-subscription-attacks/cross-tenant-identity-attacks.md#b2b-guest-users` | B2B guest users |  | EXCLUDED | Guest default permissions are enumeration; any privileged roles/groups held by guests are evaluated by the regular Entra entries. |
| `az-cross-tenant-and-cross-subscription-attacks/cross-tenant-identity-attacks.md#multi-tenant-apps-and-oauth-consent-illicit-consent-grant` | Multi-tenant apps and OAuth consent (illicit consent grant) |  | EXCLUDED | Phishing / user interaction; not a permission-derived edge. |
| `az-cross-tenant-and-cross-subscription-attacks/cross-tenant-identity-attacks.md#cross-tenant-access-settings` | Cross-tenant access settings |  | EXCLUDED | Policy that relaxes inbound trust (MFA/device claims); a bypass, no new principal. |
| `az-cross-tenant-and-cross-subscription-attacks/cross-tenant-identity-attacks.md#cross-tenant-synchronization` | Cross-tenant synchronization |  | EXCLUDED | Persistence across tenants; the source tenant is out of the scanned graph. |
| `az-cross-tenant-and-cross-subscription-attacks/cross-tenant-identity-attacks.md#federation--domain-trust-backdoor` | Federation / domain-trust backdoor |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-entraid-privesc/README.md#federation---trusted-domain` |
| `az-cross-tenant-and-cross-subscription-attacks/cross-tenant-identity-attacks.md#noauth-and-foci` | nOAuth and FOCI |  | EXCLUDED | Application-side identity confusion / token reuse by the same principal; not expressible from tenant configuration. |
| `az-cross-tenant-and-cross-subscription-attacks/cross-tenant-identity-attacks.md#workload-identity-federation-cross-cloud-confused-deputy` | Workload identity federation (cross-cloud confused deputy) |  | EXCLUDED | External-IdP trust; adding a FIC is covered by the application/SP credential-update entries. |
| `az-cross-tenant-and-cross-subscription-attacks/cross-tenant-identity-attacks.md#adding-credentials-to-an-existing-app--service-principal` | Adding credentials to an existing app / service principal |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-entraid-privesc/README.md#applicationreadwriteall`, `az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectoryapplicationsownersupdate`, `az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectoryserviceprincipalsownersupdate` |
| `az-cross-tenant-and-cross-subscription-attacks/cross-tenant-identity-attacks.md#enumeration` | Enumeration |  | STRUCTURAL | title/reference/intro heading |
| `az-cross-tenant-and-cross-subscription-attacks/cross-tenant-identity-attacks.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-cross-tenant-and-cross-subscription-attacks/detection-and-hardening.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-cross-tenant-and-cross-subscription-attacks/detection-and-hardening.md` | (page) |  | STRUCTURAL | page reviewed: cross-tenant: phishing/consent, trust-setting bypass, out-of-graph source tenant, or data-plane sharing |
| `az-cross-tenant-and-cross-subscription-attacks/detection-and-hardening.md#az---cross-tenant-detection--hardening` | Az - Cross-Tenant Detection & Hardening |  | STRUCTURAL | title/reference/intro heading |
| `az-cross-tenant-and-cross-subscription-attacks/detection-and-hardening.md#build-the-cross-boundary-trust-graph` | Build the cross-boundary trust graph |  | EXCLUDED | cross-tenant: phishing/consent, trust-setting bypass, out-of-graph source tenant, or data-plane sharing |
| `az-cross-tenant-and-cross-subscription-attacks/detection-and-hardening.md#log-hunting` | Log hunting |  | EXCLUDED | cross-tenant: phishing/consent, trust-setting bypass, out-of-graph source tenant, or data-plane sharing |
| `az-cross-tenant-and-cross-subscription-attacks/detection-and-hardening.md#preventive-controls` | Preventive controls |  | EXCLUDED | cross-tenant: phishing/consent, trust-setting bypass, out-of-graph source tenant, or data-plane sharing |
| `az-cross-tenant-and-cross-subscription-attacks/detection-and-hardening.md#visibility-gaps-to-close-deliberately` | Visibility gaps to close deliberately |  | EXCLUDED | cross-tenant: phishing/consent, trust-setting bypass, out-of-graph source tenant, or data-plane sharing |
| `az-cross-tenant-and-cross-subscription-attacks/detection-and-hardening.md#incident-response` | Incident response |  | EXCLUDED | cross-tenant: phishing/consent, trust-setting bypass, out-of-graph source tenant, or data-plane sharing |
| `az-cross-tenant-and-cross-subscription-attacks/detection-and-hardening.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-cross-tenant-and-cross-subscription-attacks/historical-cross-tenant-vulnerabilities.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-cross-tenant-and-cross-subscription-attacks/historical-cross-tenant-vulnerabilities.md` | (page) |  | STRUCTURAL | page reviewed: cross-tenant: phishing/consent, trust-setting bypass, out-of-graph source tenant, or data-plane sharing |
| `az-cross-tenant-and-cross-subscription-attacks/historical-cross-tenant-vulnerabilities.md#az---historical-cross-tenant-vulnerabilities` | Az - Historical Cross-Tenant Vulnerabilities |  | STRUCTURAL | title/reference/intro heading |
| `az-cross-tenant-and-cross-subscription-attacks/historical-cross-tenant-vulnerabilities.md#shared-service-tenant-isolation-escapes` | Shared-service tenant-isolation escapes |  | EXCLUDED | cross-tenant: phishing/consent, trust-setting bypass, out-of-graph source tenant, or data-plane sharing |
| `az-cross-tenant-and-cross-subscription-attacks/historical-cross-tenant-vulnerabilities.md#multi-tenant-app-and-token-trust-failures` | Multi-tenant app and token-trust failures |  | EXCLUDED | cross-tenant: phishing/consent, trust-setting bypass, out-of-graph source tenant, or data-plane sharing |
| `az-cross-tenant-and-cross-subscription-attacks/historical-cross-tenant-vulnerabilities.md#cross-tenant-abuse-of-legitimate-features-persistence` | Cross-tenant abuse of legitimate features (persistence) |  | EXCLUDED | cross-tenant: phishing/consent, trust-setting bypass, out-of-graph source tenant, or data-plane sharing |
| `az-cross-tenant-and-cross-subscription-attacks/historical-cross-tenant-vulnerabilities.md#trusted-ip-and-metadata-abuse` | Trusted-IP and metadata abuse |  | EXCLUDED | cross-tenant: phishing/consent, trust-setting bypass, out-of-graph source tenant, or data-plane sharing |
| `az-cross-tenant-and-cross-subscription-attacks/historical-cross-tenant-vulnerabilities.md#cross-subscription-not-cross-tenant-abuse-worth-noting` | Cross-subscription (not cross-tenant) abuse worth noting |  | EXCLUDED | cross-tenant: phishing/consent, trust-setting bypass, out-of-graph source tenant, or data-plane sharing |
| `az-cross-tenant-and-cross-subscription-attacks/historical-cross-tenant-vulnerabilities.md#retesting-historical-claims` | Retesting historical claims |  | EXCLUDED | cross-tenant: phishing/consent, trust-setting bypass, out-of-graph source tenant, or data-plane sharing |
| `az-cross-tenant-and-cross-subscription-attacks/historical-cross-tenant-vulnerabilities.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-cross-tenant-and-cross-subscription-attacks/resource-and-service-sharing-attacks.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-cross-tenant-and-cross-subscription-attacks/resource-and-service-sharing-attacks.md` | (page) |  | STRUCTURAL | page reviewed: cross-tenant: phishing/consent, trust-setting bypass, out-of-graph source tenant, or data-plane sharing |
| `az-cross-tenant-and-cross-subscription-attacks/resource-and-service-sharing-attacks.md#az---resource--service-sharing-attacks` | Az - Resource & Service Sharing Attacks |  | STRUCTURAL | title/reference/intro heading |
| `az-cross-tenant-and-cross-subscription-attacks/resource-and-service-sharing-attacks.md#managed-identities-across-boundaries` | Managed identities across boundaries |  | EXCLUDED | cross-tenant: phishing/consent, trust-setting bypass, out-of-graph source tenant, or data-plane sharing |
| `az-cross-tenant-and-cross-subscription-attacks/resource-and-service-sharing-attacks.md#federated-identity-credentials-cross-cloud-confused-deputy` | Federated identity credentials (cross-cloud confused deputy) |  | SUBSECTION | of #managed-identities-across-boundaries: EXCLUDED: cross-tenant: phishing/consent, trust-setting bypass, out-of-graph source tenant, or data-plane sharing |
| `az-cross-tenant-and-cross-subscription-attacks/resource-and-service-sharing-attacks.md#adding-credentials-to-an-existing-service-principal` | Adding credentials to an existing service principal |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-entraid-privesc/README.md#applicationreadwriteall`, `az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectoryserviceprincipalsownersupdate` |
| `az-cross-tenant-and-cross-subscription-attacks/resource-and-service-sharing-attacks.md#resource--service-sharing-matrix` | Resource / service sharing matrix |  | EXCLUDED | Data-plane sharing (Key Vault, SQL, Cosmos, storage) owned by the resource groups of the catalog; no Entra identity edge. |
| `az-cross-tenant-and-cross-subscription-attacks/resource-and-service-sharing-attacks.md#key-vault-sql-and-cosmos-specifics` | Key Vault, SQL and Cosmos specifics |  | EXCLUDED | cross-tenant: phishing/consent, trust-setting bypass, out-of-graph source tenant, or data-plane sharing |
| `az-cross-tenant-and-cross-subscription-attacks/resource-and-service-sharing-attacks.md#enumeration` | Enumeration |  | STRUCTURAL | title/reference/intro heading |
| `az-cross-tenant-and-cross-subscription-attacks/resource-and-service-sharing-attacks.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-device-registration.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-device-registration.md` | (page) |  | STRUCTURAL | page reviewed: explanatory / tooling / enumeration |
| `az-device-registration.md#az---device-registration--historical-vulnerabilities` | Az - Device Registration & Historical Vulnerabilities |  | STRUCTURAL | title/reference/intro heading |
| `az-device-registration.md#basic-information` | Basic Information |  | STRUCTURAL | title/reference/intro heading |
| `az-device-registration.md#tpm---trusted-platform-module` | TPM - Trusted Platform Module |  | EXCLUDED | explanatory / tooling / enumeration |
| `az-device-registration.md#historical-registering-a-device-with-sso-tokens` | Historical: Registering a device with SSO tokens |  | EXCLUDED | explanatory / tooling / enumeration |
| `az-device-registration.md#historical-overwriting-a-device-ticket` | Historical: Overwriting a device ticket |  | EXCLUDED | explanatory / tooling / enumeration |
| `az-device-registration.md#historical-overwrite-whfb-key` | Historical: Overwrite WHFB key |  | EXCLUDED | explanatory / tooling / enumeration |
| `az-device-registration.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-enumeration-tools.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-enumeration-tools.md` | (page) |  | STRUCTURAL | page reviewed: explanatory / tooling / enumeration |
| `az-enumeration-tools.md#az---enumeration-tools` | Az - Enumeration Tools |  | STRUCTURAL | title/reference/intro heading |
| `az-enumeration-tools.md#install-powershell-in-linux` | Install PowerShell in Linux |  | EXCLUDED | explanatory / tooling / enumeration |
| `az-enumeration-tools.md#install-powershell-in-macos` | Install PowerShell in MacOS |  | EXCLUDED | explanatory / tooling / enumeration |
| `az-enumeration-tools.md#main-enumeration-tools` | Main Enumeration Tools |  | EXCLUDED | explanatory / tooling / enumeration |
| `az-enumeration-tools.md#az-cli` | az cli |  | SUBSECTION | of #main-enumeration-tools: EXCLUDED: explanatory / tooling / enumeration |
| `az-enumeration-tools.md#debug--mitm-az-cli` | Debug \| MitM az cli |  | SUBSECTION | of #main-enumeration-tools: EXCLUDED: explanatory / tooling / enumeration |
| `az-enumeration-tools.md#why-the-error-happens` | Why the error happens |  | SUBSECTION | of #main-enumeration-tools: EXCLUDED: explanatory / tooling / enumeration |
| `az-enumeration-tools.md#step-by-step-working-configuration` | Step-by-step: working configuration |  | SUBSECTION | of #main-enumeration-tools: EXCLUDED: explanatory / tooling / enumeration |
| `az-enumeration-tools.md#0-prereqs` | 0) Prereqs |  | SUBSECTION | of #main-enumeration-tools: EXCLUDED: explanatory / tooling / enumeration |
| `az-enumeration-tools.md#1-create-a-standards-compliant-burp-ca-pem--key` | 1) Create a standards-compliant Burp CA (PEM + KEY) |  | SUBSECTION | of #main-enumeration-tools: EXCLUDED: explanatory / tooling / enumeration |
| `az-enumeration-tools.md#2-convert-to-pkcs12-burp-import-format` | 2) Convert to PKCS#12 (Burp import format) |  | SUBSECTION | of #main-enumeration-tools: EXCLUDED: explanatory / tooling / enumeration |
| `az-enumeration-tools.md#3-import-the-ca-into-burp` | 3) Import the CA into Burp |  | SUBSECTION | of #main-enumeration-tools: EXCLUDED: explanatory / tooling / enumeration |
| `az-enumeration-tools.md#4-trust-the-new-ca-in-macos-system-keychain` | 4) Trust the new CA in macOS system keychain |  | SUBSECTION | of #main-enumeration-tools: EXCLUDED: explanatory / tooling / enumeration |
| `az-enumeration-tools.md#5-configure-proxy-env-vars` | 5) Configure proxy env vars |  | SUBSECTION | of #main-enumeration-tools: EXCLUDED: explanatory / tooling / enumeration |
| `az-enumeration-tools.md#6-configure-requestsazure-cli-to-trust-your-burp-ca` | 6) Configure Requests/Azure CLI to trust your Burp CA |  | SUBSECTION | of #main-enumeration-tools: EXCLUDED: explanatory / tooling / enumeration |
| `az-enumeration-tools.md#7-verify-burp-is-actually-signing-with-your-new-ca-critical-check` | 7) Verify Burp is actually signing with your new CA (critical check) |  | SUBSECTION | of #main-enumeration-tools: EXCLUDED: explanatory / tooling / enumeration |
| `az-enumeration-tools.md#8-verify-python-requests-works-through-burp` | 8) Verify Python Requests works through Burp |  | SUBSECTION | of #main-enumeration-tools: EXCLUDED: explanatory / tooling / enumeration |
| `az-enumeration-tools.md#9-azure-cli-test` | 9) Azure CLI test |  | SUBSECTION | of #main-enumeration-tools: EXCLUDED: explanatory / tooling / enumeration |
| `az-enumeration-tools.md#az-powershell` | Az PowerShell |  | SUBSECTION | of #main-enumeration-tools: EXCLUDED: explanatory / tooling / enumeration |
| `az-enumeration-tools.md#debug--mitm-az-powershell` | Debug \| MitM Az PowerShell |  | SUBSECTION | of #main-enumeration-tools: EXCLUDED: explanatory / tooling / enumeration |
| `az-enumeration-tools.md#microsoft-graph-powershell` | Microsoft Graph PowerShell |  | SUBSECTION | of #main-enumeration-tools: EXCLUDED: explanatory / tooling / enumeration |
| `az-enumeration-tools.md#debug-microsoft-graph-powershell` | Debug Microsoft Graph PowerShell |  | SUBSECTION | of #main-enumeration-tools: EXCLUDED: explanatory / tooling / enumeration |
| `az-enumeration-tools.md#azuread-powershell` | ~~**AzureAD Powershell**~~ |  | SUBSECTION | of #main-enumeration-tools: EXCLUDED: explanatory / tooling / enumeration |
| `az-enumeration-tools.md#automated-recon--compliance-tools` | Automated Recon & Compliance Tools |  | EXCLUDED | explanatory / tooling / enumeration |
| `az-enumeration-tools.md#turbot-azure-plugins` | [turbot azure plugins](https://github.com/orgs/turbot/repositories?q=mod-azure) |  | SUBSECTION | of #automated-recon--compliance-tools: EXCLUDED: explanatory / tooling / enumeration |
| `az-enumeration-tools.md#prowler` | [Prowler](https://github.com/prowler-cloud/prowler) |  | SUBSECTION | of #automated-recon--compliance-tools: EXCLUDED: explanatory / tooling / enumeration |
| `az-enumeration-tools.md#monkey365` | [Monkey365](https://github.com/silverhack/monkey365) |  | SUBSECTION | of #automated-recon--compliance-tools: EXCLUDED: explanatory / tooling / enumeration |
| `az-enumeration-tools.md#scoutsuite` | [ScoutSuite](https://github.com/nccgroup/ScoutSuite) |  | SUBSECTION | of #automated-recon--compliance-tools: EXCLUDED: explanatory / tooling / enumeration |
| `az-enumeration-tools.md#azure-mg-sub-governance-reporting` | [Azure-MG-Sub-Governance-Reporting](https://github.com/JulianHayward/Azure-MG-Sub-Governance-Reporting) |  | SUBSECTION | of #automated-recon--compliance-tools: EXCLUDED: explanatory / tooling / enumeration |
| `az-enumeration-tools.md#automated-post-exploitation-tools` | Automated Post-Exploitation tools |  | EXCLUDED | explanatory / tooling / enumeration |
| `az-enumeration-tools.md#roadtools--roadrecon--roadtx` | [**ROADtools**](https://github.com/dirkjanm/ROADtools) / ROADrecon / ROADtx |  | SUBSECTION | of #automated-post-exploitation-tools: EXCLUDED: explanatory / tooling / enumeration |
| `az-enumeration-tools.md#roadrecon-collection` | ROADrecon collection |  | SUBSECTION | of #automated-post-exploitation-tools: EXCLUDED: explanatory / tooling / enumeration |
| `az-enumeration-tools.md#roadtx-high-value-use-cases` | ROADtx high-value use cases |  | SUBSECTION | of #automated-post-exploitation-tools: EXCLUDED: explanatory / tooling / enumeration |
| `az-enumeration-tools.md#roadtools-opsec--hunting-notes` | ROADtools opsec / hunting notes |  | SUBSECTION | of #automated-post-exploitation-tools: EXCLUDED: explanatory / tooling / enumeration |
| `az-enumeration-tools.md#azurehound` | [**AzureHound**](https://github.com/SpecterOps/AzureHound) |  | SUBSECTION | of #automated-post-exploitation-tools: EXCLUDED: explanatory / tooling / enumeration |
| `az-enumeration-tools.md#microburst` | [**MicroBurst**](https://github.com/NetSPI/MicroBurst) |  | SUBSECTION | of #automated-post-exploitation-tools: EXCLUDED: explanatory / tooling / enumeration |
| `az-enumeration-tools.md#powerzure` | [**PowerZure**](https://github.com/hausec/PowerZure) |  | SUBSECTION | of #automated-post-exploitation-tools: EXCLUDED: explanatory / tooling / enumeration |
| `az-enumeration-tools.md#graphrunner` | [**GraphRunner**](https://github.com/dafthack/GraphRunner/wiki/Invoke%E2%80%90GraphRunner) |  | SUBSECTION | of #automated-post-exploitation-tools: EXCLUDED: explanatory / tooling / enumeration |
| `az-enumeration-tools.md#stormspotter` | [Stormspotter](https://github.com/Azure/Stormspotter) |  | SUBSECTION | of #automated-post-exploitation-tools: EXCLUDED: explanatory / tooling / enumeration |
| `az-enumeration-tools.md#azure-resource-graph-quiet-cross-subscription-inventory` | Azure Resource Graph: quiet cross-subscription inventory |  | EXCLUDED | explanatory / tooling / enumeration |
| `az-enumeration-tools.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-lateral-movement-cloud-on-prem/README.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-lateral-movement-cloud-on-prem/README.md` | (page) |  | STRUCTURAL | page reviewed: hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/README.md#az---lateral-movement-cloud---on-prem` | Az - Lateral Movement (Cloud - On-Prem) |  | STRUCTURAL | title/reference/intro heading |
| `az-lateral-movement-cloud-on-prem/README.md#basic-information` | Basic Information |  | STRUCTURAL | title/reference/intro heading |
| `az-lateral-movement-cloud-on-prem/README.md#pivoting-techniques` | Pivoting Techniques |  | EXCLUDED | hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/README.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-lateral-movement-cloud-on-prem/az-arc-vulnerable-gpo-deploy-script.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-lateral-movement-cloud-on-prem/az-arc-vulnerable-gpo-deploy-script.md` | (page) |  | STRUCTURAL | page reviewed: hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-arc-vulnerable-gpo-deploy-script.md#az---arc-vulnerable-gpo-deploy-script` | Az - Arc vulnerable GPO Deploy Script |  | STRUCTURAL | title/reference/intro heading |
| `az-lateral-movement-cloud-on-prem/az-arc-vulnerable-gpo-deploy-script.md#identifying-the-issues` | Identifying the Issues |  | EXCLUDED | hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-arc-vulnerable-gpo-deploy-script.md#exploit` | Exploit |  | EXCLUDED | Requires on-prem domain access to the deployment share; source is outside the cloud graph. |
| `az-lateral-movement-cloud-on-prem/az-arc-vulnerable-gpo-deploy-script.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-lateral-movement-cloud-on-prem/az-cloud-kerberos-trust.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-lateral-movement-cloud-on-prem/az-cloud-kerberos-trust.md` | (page) |  | STRUCTURAL | page reviewed: hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-cloud-kerberos-trust.md#az---cloud-kerberos-trust` | Az - Cloud Kerberos Trust |  | STRUCTURAL | title/reference/intro heading |
| `az-lateral-movement-cloud-on-prem/az-cloud-kerberos-trust.md#kerberos-trust-relationship-overview` | Kerberos Trust Relationship Overview |  | EXCLUDED | hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-cloud-kerberos-trust.md#pivoting-from-entra-id-to-on-prem-ad` | Pivoting from Entra ID to On-Prem AD |  | EXCLUDED | Target is on-prem Active Directory (Domain Admin); not a cloud principal edge. |
| `az-lateral-movement-cloud-on-prem/az-cloud-kerberos-trust.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-lateral-movement-cloud-on-prem/az-cloud-sync.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-lateral-movement-cloud-on-prem/az-cloud-sync.md` | (page) |  | STRUCTURAL | page reviewed: hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-cloud-sync.md#az---cloud-sync` | Az - Cloud Sync |  | STRUCTURAL | title/reference/intro heading |
| `az-lateral-movement-cloud-on-prem/az-cloud-sync.md#basic-information` | Basic Information |  | STRUCTURAL | title/reference/intro heading |
| `az-lateral-movement-cloud-on-prem/az-cloud-sync.md#principals-generated` | Principals Generated |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-entraid-privesc/README.md#principals-generated` |
| `az-lateral-movement-cloud-on-prem/az-cloud-sync.md#password-synchronization` | Password Synchronization |  | EXCLUDED | hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-cloud-sync.md#pivoting` | Pivoting |  | EXCLUDED | hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-cloud-sync.md#ad----entra-id` | AD --> Entra ID |  | EXCLUDED | Source is on-prem agent host compromise. |
| `az-lateral-movement-cloud-on-prem/az-cloud-sync.md#entra-id----ad` | Entra ID --> AD |  | EXCLUDED | Target is on-prem Active Directory. |
| `az-lateral-movement-cloud-on-prem/az-cloud-sync.md#enumeration` | Enumeration |  | STRUCTURAL | title/reference/intro heading |
| `az-lateral-movement-cloud-on-prem/az-cloud-sync.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-lateral-movement-cloud-on-prem/az-connect-sync.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-lateral-movement-cloud-on-prem/az-connect-sync.md` | (page) |  | STRUCTURAL | page reviewed: hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-connect-sync.md#az---connect-sync` | Az - Connect Sync |  | STRUCTURAL | title/reference/intro heading |
| `az-lateral-movement-cloud-on-prem/az-connect-sync.md#basic-information` | Basic Information |  | STRUCTURAL | title/reference/intro heading |
| `az-lateral-movement-cloud-on-prem/az-connect-sync.md#principals-generated` | Principals Generated |  | EXCLUDED | hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-connect-sync.md#synchronize-passwords` | Synchronize Passwords |  | EXCLUDED | hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-connect-sync.md#password-hash-synchronization` | Password Hash Synchronization |  | SUBSECTION | of #synchronize-passwords: EXCLUDED: hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-connect-sync.md#password-writeback` | Password Writeback |  | SUBSECTION | of #synchronize-passwords: EXCLUDED: hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-connect-sync.md#pivoting-ad----entra-id` | Pivoting AD --> Entra ID |  | EXCLUDED | Source is compromise of the on-prem sync server; cloud-side roles of the sync identities are already evaluated by the generic Entra role/permission entries. |
| `az-lateral-movement-cloud-on-prem/az-connect-sync.md#enumerating-connect-sync` | Enumerating Connect Sync |  | SUBSECTION | of #pivoting-ad----entra-id: EXCLUDED: Source is compromise of the on-prem sync server; cloud-side roles of the sync identities are already evaluated by the generic Entra role/permission entries. |
| `az-lateral-movement-cloud-on-prem/az-connect-sync.md#finding-the-passwords` | Finding the passwords |  | SUBSECTION | of #pivoting-ad----entra-id: EXCLUDED: Source is compromise of the on-prem sync server; cloud-side roles of the sync identities are already evaluated by the generic Entra role/permission entries. |
| `az-lateral-movement-cloud-on-prem/az-connect-sync.md#abusing-msol_` | Abusing MSOL\_\* |  | SUBSECTION | of #pivoting-ad----entra-id: EXCLUDED: Source is compromise of the on-prem sync server; cloud-side roles of the sync identities are already evaluated by the generic Entra role/permission entries. |
| `az-lateral-movement-cloud-on-prem/az-connect-sync.md#abusing-connectsyncprovisioning_connectsync_` | Abusing ConnectSyncProvisioning_ConnectSync\_<id> |  | SUBSECTION | of #pivoting-ad----entra-id: EXCLUDED: Source is compromise of the on-prem sync server; cloud-side roles of the sync identities are already evaluated by the generic Entra role/permission entries. |
| `az-lateral-movement-cloud-on-prem/az-connect-sync.md#abusing-sync_-deprecated` | Abusing Sync\_\* [DEPRECATED] |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-entraid-privesc/README.md#abusing-sync_-deprecated` |
| `az-lateral-movement-cloud-on-prem/az-connect-sync.md#seamless-sso` | Seamless SSO |  | SUBSECTION | of #pivoting-ad----entra-id: EXCLUDED: Source is compromise of the on-prem sync server; cloud-side roles of the sync identities are already evaluated by the generic Entra role/permission entries. |
| `az-lateral-movement-cloud-on-prem/az-connect-sync.md#pivoting-entra-id----ad` | Pivoting Entra ID --> AD |  | EXCLUDED | Target is on-prem Active Directory, outside the cloud principal graph. |
| `az-lateral-movement-cloud-on-prem/az-connect-sync.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-lateral-movement-cloud-on-prem/az-domain-services.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-lateral-movement-cloud-on-prem/az-domain-services.md` | (page) |  | STRUCTURAL | page reviewed: hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-domain-services.md#az---microsoft-entra-domain-services` | Az - Microsoft Entra Domain Services |  | STRUCTURAL | title/reference/intro heading |
| `az-lateral-movement-cloud-on-prem/az-domain-services.md#domain-services` | Domain Services |  | EXCLUDED | hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-domain-services.md#pivoting` | Pivoting |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-entraid-privesc/README.md#pivoting` |
| `az-lateral-movement-cloud-on-prem/az-domain-services.md#enumeration` | Enumeration |  | STRUCTURAL | title/reference/intro heading |
| `az-lateral-movement-cloud-on-prem/az-domain-services.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-lateral-movement-cloud-on-prem/az-exchange-hybrid-impersonation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-lateral-movement-cloud-on-prem/az-exchange-hybrid-impersonation.md` | (page) |  | STRUCTURAL | page reviewed: hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-exchange-hybrid-impersonation.md#az---exchange-hybrid-impersonation-acs-actor-tokens` | Az - Exchange Hybrid Impersonation (ACS Actor Tokens) |  | STRUCTURAL | title/reference/intro heading |
| `az-lateral-movement-cloud-on-prem/az-exchange-hybrid-impersonation.md#basic-information` | Basic Information |  | STRUCTURAL | title/reference/intro heading |
| `az-lateral-movement-cloud-on-prem/az-exchange-hybrid-impersonation.md#attack-paths-and-technical-flow` | Attack Paths and Technical Flow |  | EXCLUDED | hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-exchange-hybrid-impersonation.md#modify-federation-configuration-via-exchange` | Modify Federation Configuration via Exchange |  | SUBSECTION | of #attack-paths-and-technical-flow: EXCLUDED: hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-exchange-hybrid-impersonation.md#acs-actor-tokens-and-service-to-service-impersonation` | ACS Actor Tokens and Service-to-Service Impersonation |  | EXCLUDED | Source is on-prem Exchange server compromise; the actor-token path is documented as patched. |
| `az-lateral-movement-cloud-on-prem/az-exchange-hybrid-impersonation.md#what-no-longer-works` | What No Longer Works |  | EXCLUDED | hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-exchange-hybrid-impersonation.md#what-can-still-matter-in-practice` | What Can Still Matter in Practice |  | EXCLUDED | hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-exchange-hybrid-impersonation.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-lateral-movement-cloud-on-prem/az-federation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-lateral-movement-cloud-on-prem/az-federation.md` | (page) |  | STRUCTURAL | page reviewed: hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-federation.md#az---federation` | Az - Federation |  | STRUCTURAL | title/reference/intro heading |
| `az-lateral-movement-cloud-on-prem/az-federation.md#basic-information` | Basic Information |  | STRUCTURAL | title/reference/intro heading |
| `az-lateral-movement-cloud-on-prem/az-federation.md#pivoting` | Pivoting |  | EXCLUDED | hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-federation.md#golden-saml` | Golden SAML |  | EXCLUDED | Source is on-prem AD FS key theft; the cloud-side federation backdoor is modelled by azure-entraid-domain-federation-backdoor. |
| `az-lateral-movement-cloud-on-prem/az-federation.md#recover-the-active-ad-fs-key-through-machine-dpapi` | Recover the active AD FS key through Machine DPAPI |  | SUBSECTION | of #golden-saml: EXCLUDED: Source is on-prem AD FS key theft; the cloud-side federation backdoor is modelled by azure-entraid-domain-federation-backdoor. |
| `az-lateral-movement-cloud-on-prem/az-federation.md#aws--ad-fs--golden-saml` | AWS + AD FS + Golden SAML |  | SUBSECTION | of #golden-saml: EXCLUDED: Source is on-prem AD FS key theft; the cloud-side federation backdoor is modelled by azure-entraid-domain-federation-backdoor. |
| `az-lateral-movement-cloud-on-prem/az-federation.md#on-prem---cloud` | On-prem -> cloud |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-entraid-privesc/README.md#federation---trusted-domain` |
| `az-lateral-movement-cloud-on-prem/az-federation.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-lateral-movement-cloud-on-prem/az-hybrid-identity-misc-attacks.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-lateral-movement-cloud-on-prem/az-hybrid-identity-misc-attacks.md` | (page) |  | STRUCTURAL | page reviewed: hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-hybrid-identity-misc-attacks.md#hybrid-identity-miscellaneous-attacks` | Hybrid Identity Miscellaneous Attacks |  | STRUCTURAL | title/reference/intro heading |
| `az-lateral-movement-cloud-on-prem/az-hybrid-identity-misc-attacks.md#matching-an-on-premises-account-to-an-existing-cloud-user` | Matching an on-premises account to an existing cloud user |  | EXCLUDED | Requires control of on-prem AD objects in sync scope; source is outside the cloud graph. |
| `az-lateral-movement-cloud-on-prem/az-hybrid-identity-misc-attacks.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-lateral-movement-cloud-on-prem/az-local-cloud-credentials.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-lateral-movement-cloud-on-prem/az-local-cloud-credentials.md` | (page) |  | STRUCTURAL | page reviewed: hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-local-cloud-credentials.md#az---local-cloud-credentials` | Az - Local Cloud Credentials |  | STRUCTURAL | title/reference/intro heading |
| `az-lateral-movement-cloud-on-prem/az-local-cloud-credentials.md#local-token-storage-and-security-considerations` | Local Token Storage and Security Considerations |  | EXCLUDED | hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-local-cloud-credentials.md#azure-cli-command-line-interface` | Azure CLI (Command-Line Interface) |  | SUBSECTION | of #local-token-storage-and-security-considerations: EXCLUDED: hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-local-cloud-credentials.md#azure-powershell` | Azure PowerShell |  | SUBSECTION | of #local-token-storage-and-security-considerations: EXCLUDED: hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-local-cloud-credentials.md#automatic-tools-to-find-them` | Automatic Tools to find them |  | SUBSECTION | of #local-token-storage-and-security-considerations: EXCLUDED: hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-local-cloud-credentials.md#secrets-in-azure-enumeration-artifacts` | Secrets in Azure enumeration artifacts |  | EXCLUDED | hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-local-cloud-credentials.md#validate-recovered-application-secrets` | Validate recovered application secrets |  | EXCLUDED | hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-local-cloud-credentials.md#graph-group-write-to-azure-rbac-takeover` | Graph group-write to Azure RBAC takeover |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-entraid-privesc/README.md#sensitive-graph-permissions` |
| `az-lateral-movement-cloud-on-prem/az-local-cloud-credentials.md#tokens-in-memory` | Tokens in memory |  | EXCLUDED | hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-local-cloud-credentials.md#monitoring-recovered-app-secret-usage` | Monitoring recovered app-secret usage |  | EXCLUDED | hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-local-cloud-credentials.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-lateral-movement-cloud-on-prem/az-pass-the-certificate.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-lateral-movement-cloud-on-prem/az-pass-the-certificate.md` | (page) |  | STRUCTURAL | page reviewed: hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-pass-the-certificate.md#az---pass-the-certificate` | Az - Pass the Certificate |  | STRUCTURAL | title/reference/intro heading |
| `az-lateral-movement-cloud-on-prem/az-pass-the-certificate.md#pass-the-certificate-azure` | Pass the Certificate (Azure) |  | EXCLUDED | Credential theft from a compromised device; same principal reused. |
| `az-lateral-movement-cloud-on-prem/az-pass-the-certificate.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-lateral-movement-cloud-on-prem/az-pass-the-cookie.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-lateral-movement-cloud-on-prem/az-pass-the-cookie.md` | (page) |  | STRUCTURAL | page reviewed: hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-pass-the-cookie.md#az---pass-the-cookie` | Az - Pass the Cookie |  | STRUCTURAL | title/reference/intro heading |
| `az-lateral-movement-cloud-on-prem/az-pass-the-cookie.md#why-cookies` | Why Cookies? |  | EXCLUDED | hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-pass-the-cookie.md#attack` | Attack |  | EXCLUDED | Session theft from a compromised host; same principal reused. |
| `az-lateral-movement-cloud-on-prem/az-pass-the-cookie.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-lateral-movement-cloud-on-prem/az-primary-refresh-token-prt.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-lateral-movement-cloud-on-prem/az-primary-refresh-token-prt.md` | (page) |  | STRUCTURAL | page reviewed: hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-primary-refresh-token-prt.md#az---primary-refresh-token-prt` | Az - Primary Refresh Token (PRT) |  | STRUCTURAL | title/reference/intro heading |
| `az-lateral-movement-cloud-on-prem/az-primary-refresh-token-prt.md#what-is-a-primary-refresh-token-prt` | What is a Primary Refresh Token (PRT)? |  | EXCLUDED | hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-primary-refresh-token-prt.md#how-does-a-prt-work` | How Does a PRT Work? |  | EXCLUDED | hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-primary-refresh-token-prt.md#why-are-prts-powerful` | Why are PRTs Powerful? |  | SUBSECTION | of #how-does-a-prt-work: EXCLUDED: hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-primary-refresh-token-prt.md#how-to-know-if-a-prt-is-present` | How to know if a PRT is present? |  | EXCLUDED | hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-primary-refresh-token-prt.md#pass-the-prt` | Pass the PRT |  | EXCLUDED | Token theft from a compromised device; same principal reused, no permission-derived edge. |
| `az-lateral-movement-cloud-on-prem/az-primary-refresh-token-prt.md#mimikatz` | Mimikatz |  | SUBSECTION | of #pass-the-prt: EXCLUDED: Token theft from a compromised device; same principal reused, no permission-derived edge. |
| `az-lateral-movement-cloud-on-prem/az-primary-refresh-token-prt.md#mimikatz--aadinternals` | Mimikatz + AADInternals |  | SUBSECTION | of #pass-the-prt: EXCLUDED: Token theft from a compromised device; same principal reused, no permission-derived edge. |
| `az-lateral-movement-cloud-on-prem/az-primary-refresh-token-prt.md#mimikatz--roadtx` | Mimikatz + roadtx |  | SUBSECTION | of #pass-the-prt: EXCLUDED: Token theft from a compromised device; same principal reused, no permission-derived edge. |
| `az-lateral-movement-cloud-on-prem/az-primary-refresh-token-prt.md#mimikatz--roadrecon` | Mimikatz + roadrecon |  | SUBSECTION | of #pass-the-prt: EXCLUDED: Token theft from a compromised device; same principal reused, no permission-derived edge. |
| `az-lateral-movement-cloud-on-prem/az-primary-refresh-token-prt.md#abusing-protected-prts` | Abusing protected PRTs |  | EXCLUDED | hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-primary-refresh-token-prt.md#windows-token-broker-architecture-and-sso-flow` | Windows Token Broker Architecture and SSO Flow |  | SUBSECTION | of #abusing-protected-prts: EXCLUDED: hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-primary-refresh-token-prt.md#user-level-token-theft-non-admin` | User-Level Token Theft (Non-Admin) |  | SUBSECTION | of #abusing-protected-prts: EXCLUDED: hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-primary-refresh-token-prt.md#browsercore-microsoftaccounttokenprovider-com` | **BrowserCore (MicrosoftAccountTokenProvider COM)** |  | SUBSECTION | of #abusing-protected-prts: EXCLUDED: hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-primary-refresh-token-prt.md#web-account-manager-wam-apis` | **Web Account Manager (WAM) APIs** |  | SUBSECTION | of #abusing-protected-prts: EXCLUDED: hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-primary-refresh-token-prt.md#administrator--system-level-token-abuse` | Administrator / SYSTEM-Level Token Abuse |  | SUBSECTION | of #abusing-protected-prts: EXCLUDED: hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-primary-refresh-token-prt.md#user-impersonation-and-token-retrieval` | **User Impersonation and Token Retrieval** |  | SUBSECTION | of #abusing-protected-prts: EXCLUDED: hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-primary-refresh-token-prt.md#direct-lsass--token-broker-interaction-advanced` | **Direct LSASS & Token Broker Interaction (Advanced)** |  | SUBSECTION | of #abusing-protected-prts: EXCLUDED: hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-primary-refresh-token-prt.md#phishing-prts` | Phishing PRTs |  | EXCLUDED | hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-primary-refresh-token-prt.md#why-this-works` | **Why this works** |  | SUBSECTION | of #phishing-prts: EXCLUDED: hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-primary-refresh-token-prt.md#public-tools-and-proof-of-concepts` | Public Tools and Proof-of-Concepts |  | SUBSECTION | of #phishing-prts: EXCLUDED: hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-primary-refresh-token-prt.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-lateral-movement-cloud-on-prem/az-pta-pass-through-authentication.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-lateral-movement-cloud-on-prem/az-pta-pass-through-authentication.md` | (page) |  | STRUCTURAL | page reviewed: hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-pta-pass-through-authentication.md#az---pta---pass-through-authentication` | Az - PTA - Pass-through Authentication |  | STRUCTURAL | title/reference/intro heading |
| `az-lateral-movement-cloud-on-prem/az-pta-pass-through-authentication.md#basic-information` | Basic Information |  | STRUCTURAL | title/reference/intro heading |
| `az-lateral-movement-cloud-on-prem/az-pta-pass-through-authentication.md#authentication-flow` | Authentication flow |  | EXCLUDED | hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-pta-pass-through-authentication.md#enumeration` | Enumeration |  | STRUCTURAL | title/reference/intro heading |
| `az-lateral-movement-cloud-on-prem/az-pta-pass-through-authentication.md#pivoting` | Pivoting |  | EXCLUDED | Source is on-prem PTA agent host compromise. |
| `az-lateral-movement-cloud-on-prem/az-pta-pass-through-authentication.md#seamless-sso` | Seamless SSO |  | SUBSECTION | of #pivoting: EXCLUDED: Source is on-prem PTA agent host compromise. |
| `az-lateral-movement-cloud-on-prem/az-pta-pass-through-authentication.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-lateral-movement-cloud-on-prem/az-seamless-sso.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-lateral-movement-cloud-on-prem/az-seamless-sso.md` | (page) |  | STRUCTURAL | page reviewed: hybrid identity: source is on-prem/host compromise or target is on-prem AD; same-principal token theft |
| `az-lateral-movement-cloud-on-prem/az-seamless-sso.md#az---seamless-sso` | Az - Seamless SSO |  | STRUCTURAL | title/reference/intro heading |
| `az-lateral-movement-cloud-on-prem/az-seamless-sso.md#basic-information` | Basic Information |  | STRUCTURAL | title/reference/intro heading |
| `az-lateral-movement-cloud-on-prem/az-seamless-sso.md#enumeration` | Enumeration |  | STRUCTURAL | title/reference/intro heading |
| `az-lateral-movement-cloud-on-prem/az-seamless-sso.md#pivoting-on-prem---cloud` | Pivoting: On-prem -> cloud |  | EXCLUDED | Source is on-prem AD compromise. |
| `az-lateral-movement-cloud-on-prem/az-seamless-sso.md#seamlesspass` | [**SeamlessPass**](https://github.com/Malcrove/SeamlessPass) |  | SUBSECTION | of #pivoting-on-prem---cloud: EXCLUDED: Source is on-prem AD compromise. |
| `az-lateral-movement-cloud-on-prem/az-seamless-sso.md#getting-hashes-of-the-azureadssoacc-account` | Getting hashes of the AZUREADSSOACC$ account |  | SUBSECTION | of #pivoting-on-prem---cloud: EXCLUDED: Source is on-prem AD compromise. |
| `az-lateral-movement-cloud-on-prem/az-seamless-sso.md#creating-silver-tickets` | Creating Silver Tickets |  | SUBSECTION | of #pivoting-on-prem---cloud: EXCLUDED: Source is on-prem AD compromise. |
| `az-lateral-movement-cloud-on-prem/az-seamless-sso.md#using-silver-tickets-with-firefox` | Using Silver Tickets with Firefox |  | SUBSECTION | of #pivoting-on-prem---cloud: EXCLUDED: Source is on-prem AD compromise. |
| `az-lateral-movement-cloud-on-prem/az-seamless-sso.md#on-prem---cloud-via-resource-based-constrained-delegation` | On-prem -> Cloud via Resource Based Constrained Delegation |  | SUBSECTION | of #pivoting-on-prem---cloud: EXCLUDED: Source is on-prem AD compromise. |
| `az-lateral-movement-cloud-on-prem/az-seamless-sso.md#creating-kerberos-tickets-for-cloud-only-users` | ~~Creating Kerberos tickets for cloud-only users~~ |  | SUBSECTION | of #pivoting-on-prem---cloud: EXCLUDED: Source is on-prem AD compromise. |
| `az-lateral-movement-cloud-on-prem/az-seamless-sso.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-permissions-for-a-pentest.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-permissions-for-a-pentest.md` | (page) |  | STRUCTURAL | page reviewed: explanatory / tooling / enumeration |
| `az-permissions-for-a-pentest.md#az---permissions-for-a-pentest` | Az - Permissions for a Pentest |  | STRUCTURAL | title/reference/intro heading |
| `az-permissions-for-a-pentest.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-persistence/README.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/README.md` | (page) |  | STRUCTURAL | page reviewed: persistence / defense evasion: no new principal gained |
| `az-persistence/README.md#az---persistence` | Az - Persistence |  | STRUCTURAL | title/reference/intro heading |
| `az-persistence/README.md#azure` | Azure |  | EXCLUDED | persistence / defense evasion: no new principal gained |
| `az-persistence/README.md#persistence-categories` | Persistence categories |  | EXCLUDED | persistence / defense evasion: no new principal gained |
| `az-persistence/README.md#how-to-read-these-pages` | How to read these pages |  | STRUCTURAL | title/reference/intro heading |
| `az-persistence/README.md#stealth-scale` | Stealth scale |  | STRUCTURAL | title/reference/intro heading |
| `az-persistence/README.md#standing-access-grants` | Standing access grants |  | EXCLUDED | persistence / defense evasion: no new principal gained |
| `az-persistence/README.md#oauth-application` | OAuth Application |  | EXCLUDED | Requires an administrator who can already grant those permissions (covered by role/Graph entries); otherwise persistence/phishing only. |
| `az-persistence/README.md#federation---trusted-domain` | Federation - Trusted Domain |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-entraid-privesc/README.md#federation---trusted-domain` |
| `az-persistence/README.md#rogue-certificate-authority-in-the-tenant-cba-trust-store` | Rogue Certificate Authority in the tenant CBA trust store |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-entraid-privesc/README.md#rogue-certificate-authority-in-the-tenant-cba-trust-store` |
| `az-persistence/README.md#reusable-credentials` | Reusable credentials |  | EXCLUDED | persistence / defense evasion: no new principal gained |
| `az-persistence/README.md#applications-and-service-principals` | Applications and Service Principals |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-entraid-privesc/README.md#applicationreadwriteall`, `az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectoryapplicationsownersupdate` |
| `az-persistence/README.md#federation---token-signing-certificate` | Federation - Token Signing Certificate |  | EXCLUDED | Requires on-premises Domain Admin / AD FS server control; on-prem to cloud pivot outside the Entra snapshot. |
| `az-persistence/README.md#restricted-management-administrative-unit-rmau-to-shield-backdoor-objects` | Restricted Management Administrative Unit (RMAU) to shield backdoor objects |  | EXCLUDED | Persistence / anti-remediation; the restricted_management_au blocker already models its effect on other edges. |
| `az-persistence/README.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-persistence/az-ai-foundry-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-ai-foundry-persistence.md` |  |  | STRUCTURAL | page reviewed: persistence techniques for an already-held foothold (data-plane grants, credentials, backdoors); no new Azure/Entra principal beyond entries noted per heading |
| `az-persistence/az-ai-foundry-persistence.md#az---ai-foundry-persistence` | Az - AI Foundry Persistence |  | STRUCTURAL | page title |
| `az-persistence/az-ai-foundry-persistence.md#ai-foundry` | AI Foundry |  | STRUCTURAL | section grouping heading |
| `az-persistence/az-ai-foundry-persistence.md#code-and-artifact-backdoors` | Code and artifact backdoors |  | STRUCTURAL | section grouping heading |
| `az-persistence/az-ai-foundry-persistence.md#microsoftcognitiveservicesaccountsopenaifine-tuneswrite--model-backdoor--poison-via-fine-tuning` | `Microsoft.CognitiveServices/accounts/OpenAI/fine-tunes/write` — model backdoor / poison via fine-tuning | Microsoft.CognitiveServices/accounts/OpenAI/fine-tunes/write | EXCLUDED | Persistence/data-plane technique; no new Azure/Entra principal. |
| `az-persistence/az-ai-foundry-persistence.md#microsoftcognitiveservicesaccountsaiservicesagentswrite--foundry-agent-poisoning` | `Microsoft.CognitiveServices/accounts/AIServices/agents/write` — Foundry agent poisoning | Microsoft.CognitiveServices/accounts/AIServices/agents/write | EXCLUDED | Persistence/data-plane technique; no new Azure/Entra principal. |
| `az-persistence/az-ai-foundry-persistence.md#references` | References |  | STRUCTURAL | section grouping heading |

## az-persistence/az-analysis-services-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-analysis-services-persistence.md` |  |  | STRUCTURAL | page reviewed: persistence techniques for an already-held foothold (data-plane grants, credentials, backdoors); no new Azure/Entra principal beyond entries noted per heading |
| `az-persistence/az-analysis-services-persistence.md#az---analysis-services-persistence` | Az - Analysis Services Persistence |  | STRUCTURAL | page title |
| `az-persistence/az-analysis-services-persistence.md#analysis-services` | Analysis Services |  | STRUCTURAL | section grouping heading |
| `az-persistence/az-analysis-services-persistence.md#data-model-role-tampering-for-persistence` | Data-model role tampering for persistence |  | EXCLUDED | Persistence/data-plane technique; no new Azure/Entra principal. |
| `az-persistence/az-analysis-services-persistence.md#references` | References |  | STRUCTURAL | section grouping heading |

## az-persistence/az-automation-accounts-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-automation-accounts-persistence.md#backdoor-an-existing-runbook` | Backdoor an existing runbook |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-automation-accounts-privesc.md#microsoftautomationautomationaccountsjobswrite-microsoftautomationautomationaccountsrunbooksdraftwrite-microsoftautomationautomationaccountsrunbooksdraftcontentwrite-microsoftautomationautomationaccountsjobsoutputread-microsoftautomationautomationaccountsrunbookspublishaction-microsoftresourcessubscriptionsresourcegroupsread-microsoftautomationautomationaccountsrunbookswrite` |
| `az-persistence/az-automation-accounts-persistence.md#malware-on-a-vm-in-a-hybrid-runbook-worker-group` | Malware on a VM in a Hybrid Runbook Worker group |  | EXCLUDED | Requires host compromise of the worker VM; the RBAC route to worker identities is azure-automation-runbook-hybrid-worker. |
| `az-persistence/az-automation-accounts-persistence.md#compromise-external-repositories` | Compromise external repositories |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-automation-accounts-privesc.md#microsoftautomationautomationaccountssourcecontrolswrite-microsoftautomationautomationaccountssourcecontrolsread` |
| `az-persistence/az-automation-accounts-persistence.md#watcher-tasks-sub-schedule-floor-recurring-execution` | Watcher tasks: sub-schedule-floor recurring execution |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-automation-accounts-privesc.md#microsoftautomationautomationaccountsjobswrite-microsoftautomationautomationaccountsrunbooksdraftwrite-microsoftautomationautomationaccountsrunbooksdraftcontentwrite-microsoftautomationautomationaccountsjobsoutputread-microsoftautomationautomationaccountsrunbookspublishaction-microsoftresourcessubscriptionsresourcegroupsread-microsoftautomationautomationaccountsrunbookswrite` |
| `az-persistence/az-automation-accounts-persistence.md#schedules-and-webhooks` | Schedules and webhooks |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-automation-accounts-privesc.md#abuse-jobscheduleswrite-to-run-an-existing-privileged-runbook`, `az-privilege-escalation/az-automation-accounts-privesc.md#microsoftautomationautomationaccountsjobswrite-microsoftautomationautomationaccountsrunbooksdraftwrite-microsoftautomationautomationaccountsrunbooksdraftcontentwrite-microsoftautomationautomationaccountsjobsoutputread-microsoftautomationautomationaccountsrunbookspublishaction-microsoftresourcessubscriptionsresourcegroupsread-microsoftautomationautomationaccountsrunbookswrite` |
| `az-persistence/az-automation-accounts-persistence.md` | Az - Automation Accounts Persistence |  | EXCLUDED | page reviewed: persistence techniques; rows below |

## az-persistence/az-batch-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-batch-persistence.md` |  |  | STRUCTURAL | page reviewed: persistence of an already-held foothold; identity-relevant sections mapped/excluded per heading |
| `az-persistence/az-batch-persistence.md#interactive-admin-persistence-via-compute-node-user--remote-login-data-plane` | Interactive admin persistence via compute-node user + remote login (data-plane) |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-batch-privesc.md#microsoftbatchbatchaccountslistkeysaction` |

## az-persistence/az-chaos-studio-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-chaos-studio-persistence.md` |  |  | STRUCTURAL | page reviewed: persistence of an already-held foothold; identity-relevant sections mapped/excluded per heading |
| `az-persistence/az-chaos-studio-persistence.md#pre-stage-a-kill-switch` | Pre-stage a kill switch | Microsoft.Authorization/roleAssignments/write,Microsoft.Chaos/experiments/write,Microsoft.Chaos/targets/write | EXCLUDED | Security-control weakening, telemetry tampering or DoS; no Azure/Entra principal is obtained. |

## az-persistence/az-cloud-shell-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-cloud-shell-persistence.md` |  |  | STRUCTURAL | page reviewed: persistence of an already-held foothold; identity-relevant sections mapped/excluded per heading |
| `az-persistence/az-cloud-shell-persistence.md#backdoor-cloud-shell-startup-files` | Backdoor Cloud Shell startup files |  | EXCLUDED | Backdoors the caller's own Cloud Shell home; another user's home is azure-cloudshell-home-image-backdoor. |
| `az-persistence/az-cloud-shell-persistence.md#cloud-shell-phishing` | Cloud Shell Phishing |  | EXCLUDED | Strict principal-boundary audit: The credential_stored_in_scope selector has no exact usable credential and identified target-principal evidence enforcement for this technique; a secret read or arbitrary configuration change alone is not an established principal escalation. |

## az-persistence/az-container-apps-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-container-apps-persistence.md` |  |  | STRUCTURAL | page reviewed: persistence of an already-held foothold; identity-relevant sections mapped/excluded per heading |
| `az-persistence/az-container-apps-persistence.md#microsoftappcontainerappsauthconfigswrite--easy-auth-bypass-or-identity-provider-replacement` | `Microsoft.App/containerApps/authConfigs/write` — Easy Auth bypass or identity provider replacement | Microsoft.App/containerApps/*/write,Microsoft.App/containerApps/authConfigs/write | EXCLUDED | Easy Auth bypass / IdP repoint gives application-level access only; no Azure/Entra principal. |
| `az-persistence/az-container-apps-persistence.md#microsoftappcontainerappssourcecontrolswrite--repoint-github-actions-deployment` | `Microsoft.App/containerApps/sourcecontrols/write` — Repoint GitHub Actions deployment | Microsoft.App/containerApps/*/write,Microsoft.App/containerApps/sourcecontrols/write | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-container-apps-privesc.md#microsoftappcontainerappssourcecontrolswrite--repoint-github-actions-deployment` |

## az-persistence/az-container-registry-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-container-registry-persistence.md` |  |  | STRUCTURAL | page reviewed: persistence of an already-held foothold; identity-relevant sections mapped/excluded per heading |
| `az-persistence/az-container-registry-persistence.md#microsoftcontainerregistryregistrieslistcredentialsaction-microsoftcontainerregistryregistrieswrite` | `Microsoft.ContainerRegistry/registries/listCredentials/action`, `Microsoft.ContainerRegistry/registries/write` | Microsoft.ContainerRegistry/registries/listCredentials/action,Microsoft.ContainerRegistry/registries/write | EXCLUDED | Registry admin credential persistence; registry push/pull only (consumer pivot is azure-acr-push-restart-aci-consumer). |
| `az-persistence/az-container-registry-persistence.md#create-a-service-principal-with-acrpull` | Create a service principal with AcrPull |  | EXCLUDED | Creates an attacker-owned principal with AcrPull; persistence of registry read access, requires app/role-assignment write modelled elsewhere. |

## az-persistence/az-cost-management-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-cost-management-persistence.md#budget-triggered-action-group-as-a-persistent-trigger` | Budget-triggered Action Group as a persistent trigger |  | EXCLUDED | Strict principal-boundary audit: The source permission or capability needed to perform the stated write/action is absent from requires; reviewed target evidence alone cannot establish the X permission to Y action escalation path. |
| `az-persistence/az-cost-management-persistence.md` | Az - Cost Management Persistence |  | EXCLUDED | page reviewed: persistence techniques; rows below |

## az-persistence/az-data-explorer-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-data-explorer-persistence.md` |  |  | STRUCTURAL | page reviewed: persistence techniques for an already-held foothold (data-plane grants, credentials, backdoors); no new Azure/Entra principal beyond entries noted per heading |
| `az-persistence/az-data-explorer-persistence.md#az---data-explorer-persistence` | Az - Data Explorer Persistence |  | STRUCTURAL | page title |
| `az-persistence/az-data-explorer-persistence.md#data-explorer` | Data Explorer |  | STRUCTURAL | section grouping heading |
| `az-persistence/az-data-explorer-persistence.md#data-plane-add-databasecluster-admins--persistence-that-evades-arm-review` | Data-plane `.add database/cluster admins` — persistence that evades ARM review |  | EXCLUDED | Persistence/data-plane technique; no new Azure/Entra principal. |

## az-persistence/az-data-factory-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-data-factory-persistence.md` |  |  | STRUCTURAL | page reviewed: persistence techniques for an already-held foothold (data-plane grants, credentials, backdoors); no new Azure/Entra principal beyond entries noted per heading |
| `az-persistence/az-data-factory-persistence.md#az---data-factory-persistence` | Az - Data Factory Persistence |  | STRUCTURAL | page title |
| `az-persistence/az-data-factory-persistence.md#data-factory` | Data Factory |  | STRUCTURAL | section grouping heading |
| `az-persistence/az-data-factory-persistence.md#redirect-a-schedule-trigger-with-triggerswrite--stopstart` | Redirect a schedule trigger with `triggers/write` + `stop`/`start` | Microsoft.DataFactory/factories/triggers/start/action,Microsoft.DataFactory/factories/triggers/stop/action,Microsoft.DataFactory/factories/triggers/write | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-data-factory-privesc.md#redirect-factory-output-through-microsoftdatafactoryfactoriesglobalparameterswrite` |

## az-persistence/az-databricks-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-databricks-persistence.md` |  |  | STRUCTURAL | page reviewed: persistence techniques for an already-held foothold (data-plane grants, credentials, backdoors); no new Azure/Entra principal beyond entries noted per heading |
| `az-persistence/az-databricks-persistence.md#az---databricks-persistence` | Az - Databricks Persistence |  | STRUCTURAL | page title |
| `az-persistence/az-databricks-persistence.md#databricks` | Databricks |  | STRUCTURAL | section grouping heading |
| `az-persistence/az-databricks-persistence.md#global-init-scripts--workspace-wide-persistent-rce` | Global init scripts — workspace-wide persistent RCE |  | EXCLUDED | Strict principal-boundary audit: The source permission or capability needed to perform the stated write/action is absent from requires; reviewed target evidence alone cannot establish the X permission to Y action escalation path. |
| `az-persistence/az-databricks-persistence.md#personal-access-token-pat-minting-for-persistence` | Personal Access Token (PAT) minting for persistence |  | EXCLUDED | Persistence of the caller's own Databricks identity; no new principal. |
| `az-persistence/az-databricks-persistence.md#references` | References |  | STRUCTURAL | section grouping heading |

## az-persistence/az-defender-for-cloud-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-defender-for-cloud-persistence.md#permanent-suppression-rule-scoped-to-your-source` | Permanent suppression rule scoped to your source |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-defender-for-cloud-persistence.md#auto-provisioning-off--born-blind-new-resources` | Auto-provisioning off — born-blind new resources |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-defender-for-cloud-persistence.md#continuous-export-gap` | Continuous-export gap |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-defender-for-cloud-persistence.md#silenced-notifications` | Silenced notifications |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-defender-for-cloud-persistence.md#plan-downgrade-held-in-place-by-azure-policy` | Plan downgrade held in place by Azure Policy |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-defender-for-cloud-persistence.md` | Az - Defender for Cloud Persistence |  | EXCLUDED | page reviewed: persistence techniques; rows below |

## az-persistence/az-deployment-stacks-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-deployment-stacks-persistence.md#deny-settings-lockout-without-denyassignmentswrite-anti-remediation-persistence` | Deny-settings lockout without `denyAssignments/write` (anti-remediation persistence) |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-deployment-stacks-persistence.md` | Az - Deployment Stacks Persistence |  | EXCLUDED | page reviewed: persistence techniques; rows below |

## az-persistence/az-dev-center-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-dev-center-persistence.md` |  |  | STRUCTURAL | page reviewed: persistence of an already-held foothold; identity-relevant sections mapped/excluded per heading |
| `az-persistence/az-dev-center-persistence.md#code-and-artifact-backdoors` | Code and artifact backdoors |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-dev-center-privesc.md#ade-deployment-identity-template-injection-marquee-privesc` |

## az-persistence/az-devtest-labs-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-devtest-labs-persistence.md` |  |  | STRUCTURAL | page reviewed: persistence of an already-held foothold; identity-relevant sections mapped/excluded per heading |
| `az-persistence/az-devtest-labs-persistence.md#malicious-artifact-source-supply-chain-into-the-lab` | Malicious artifact source (supply-chain into the lab) | Microsoft.DevTestLab/labs/artifactSources/write | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-devtest-labs-privesc.md#applyartifacts--in-guest-rce--managed-identity-theft-marquee` |
| `az-persistence/az-devtest-labs-persistence.md#poison-formulas--custom-images-provisioning-time-persistence` | Poison formulas / custom images (provisioning-time persistence) | Microsoft.DevTestLab/labs/customImages/write,Microsoft.DevTestLab/labs/formulas/write | EXCLUDED | Provisioning-time supply chain for future lab VMs created by others; consumer-dependent, not RBAC-derivable. |
| `az-persistence/az-devtest-labs-persistence.md#seed-attacker-known-credentials-via-labuser-secrets` | Seed attacker-known credentials via lab/user secrets | Microsoft.DevTestLab/labs/secrets/write,Microsoft.DevTestLab/labs/users/secrets/write | EXCLUDED | Seeds lab/user secrets for later use; persistence of access already held. |

## az-persistence/az-entra-id-governance-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-entra-id-governance-persistence.md` | (page) |  | STRUCTURAL | page reviewed: persistence / defense evasion: no new principal gained |
| `az-persistence/az-entra-id-governance-persistence.md#az---entra-id-governance-persistence` | Az - Entra ID Governance Persistence |  | STRUCTURAL | title/reference/intro heading |
| `az-persistence/az-entra-id-governance-persistence.md#entra-id-governance` | Entra ID Governance |  | EXCLUDED | persistence / defense evasion: no new principal gained |
| `az-persistence/az-entra-id-governance-persistence.md#standing-access-grants` | Standing access grants |  | EXCLUDED | persistence / defense evasion: no new principal gained |
| `az-persistence/az-entra-id-governance-persistence.md#connectedorganization-standing-backdoor-persistence` | connectedOrganization standing backdoor (persistence) |  | SUBSECTION | of #standing-access-grants: EXCLUDED: persistence / defense evasion: no new principal gained |
| `az-persistence/az-entra-id-governance-persistence.md#backdoor-approver--policy-tamper-on-existing-packages-persistence` | Backdoor approver / policy tamper on existing packages (persistence) |  | SUBSECTION | of #standing-access-grants: EXCLUDED: persistence / defense evasion: no new principal gained |
| `az-persistence/az-entra-id-governance-persistence.md#auto-assignment-policy-abuse-persistence` | Auto-assignment policy abuse (persistence) |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-entra-id-governance-privesc.md#auto-assignment-policy-abuse-persistence` |
| `az-persistence/az-entra-id-governance-persistence.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-persistence/az-entra-id-protection-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-entra-id-protection-persistence.md` | (page) |  | STRUCTURAL | page reviewed: persistence / defense evasion: no new principal gained |
| `az-persistence/az-entra-id-protection-persistence.md#az---entra-id-protection-persistence` | Az - Entra ID Protection Persistence |  | STRUCTURAL | title/reference/intro heading |
| `az-persistence/az-entra-id-protection-persistence.md#entra-id-protection` | Entra ID Protection |  | EXCLUDED | persistence / defense evasion: no new principal gained |
| `az-persistence/az-entra-id-protection-persistence.md#persistent-defense-evasion` | Persistent defense evasion |  | EXCLUDED | persistence / defense evasion: no new principal gained |
| `az-persistence/az-entra-id-protection-persistence.md#standing-risk-dismissal-and-allow-listing` | Standing risk dismissal and allow-listing |  | SUBSECTION | of #persistent-defense-evasion: EXCLUDED: persistence / defense evasion: no new principal gained |
| `az-persistence/az-entra-id-protection-persistence.md#exclude-a-controlled-principal-from-risk-based-conditional-access` | Exclude a controlled principal from risk-based Conditional Access |  | SUBSECTION | of #persistent-defense-evasion: EXCLUDED: persistence / defense evasion: no new principal gained |
| `az-persistence/az-entra-id-protection-persistence.md#exclude-a-controlled-principal-from-risk-remediation-requirements` | Exclude a controlled principal from risk remediation requirements |  | SUBSECTION | of #persistent-defense-evasion: EXCLUDED: persistence / defense evasion: no new principal gained |
| `az-persistence/az-entra-id-protection-persistence.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-persistence/az-entraid-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-entraid-persistence.md` | (page) |  | STRUCTURAL | page reviewed: persistence / defense evasion: no new principal gained |
| `az-persistence/az-entraid-persistence.md#az---entra-id-persistence` | Az - Entra ID Persistence |  | STRUCTURAL | title/reference/intro heading |
| `az-persistence/az-entraid-persistence.md#entra-id` | Entra ID |  | EXCLUDED | persistence / defense evasion: no new principal gained |
| `az-persistence/az-entraid-persistence.md#federated-identity-credential-on-an-application` | Federated identity credential on an application |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectoryapplicationsownersupdate`, `az-privilege-escalation/az-entraid-privesc/README.md#applicationreadwriteall` |
| `az-persistence/az-entraid-persistence.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-persistence/az-event-hubs-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-event-hubs-persistence.md#covert-consumer-group--silent-stream-tap-consumergroupswrite` | Covert consumer group — silent stream tap (`consumergroups/write`) |  | EXCLUDED | Strict principal-boundary audit: The declared target is a bounded authority rather than an identified target principal or an explicit grant of extra permissions to the caller. |
| `az-persistence/az-event-hubs-persistence.md#geo-dr-alias-redirection-persistence-disasterrecoveryconfigswrite` | Geo-DR alias redirection persistence (`disasterRecoveryConfigs/write`) |  | EXCLUDED | Strict principal-boundary audit: The declared target is a bounded authority rather than an identified target principal or an explicit grant of extra permissions to the caller. |
| `az-persistence/az-event-hubs-persistence.md#capture-archive-as-a-durable-exfil-feed-eventhubswrite` | Capture archive as a durable exfil feed (`eventhubs/write`) |  | EXCLUDED | Strict principal-boundary audit: The declared target is a bounded authority rather than an identified target principal or an explicit grant of extra permissions to the caller. |
| `az-persistence/az-event-hubs-persistence.md#self-minted-entity-sas-rule--durable-bearer-credential` | Self-minted entity SAS rule — durable bearer credential |  | EXCLUDED | Strict principal-boundary audit: The declared target is a bounded authority rather than an identified target principal or an explicit grant of extra permissions to the caller. |
| `az-persistence/az-event-hubs-persistence.md#re-enable-local-sas-authentication-disablelocalauthfalse` | Re-enable local SAS authentication (`disableLocalAuth=false`) |  | EXCLUDED | Strict principal-boundary audit: The declared target is a bounded authority rather than an identified target principal or an explicit grant of extra permissions to the caller. |
| `az-persistence/az-event-hubs-persistence.md` | Az - Event Hubs Persistence |  | EXCLUDED | page reviewed: persistence techniques; rows below |

## az-persistence/az-fabric-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-fabric-persistence.md` |  |  | STRUCTURAL | page reviewed: persistence techniques for an already-held foothold (data-plane grants, credentials, backdoors); no new Azure/Entra principal beyond entries noted per heading |
| `az-persistence/az-fabric-persistence.md#az---fabric-persistence` | Az - Fabric Persistence |  | STRUCTURAL | page title |
| `az-persistence/az-fabric-persistence.md#fabric` | Fabric |  | STRUCTURAL | section grouping heading |
| `az-persistence/az-fabric-persistence.md#service-principal-persistence-as-a-workspace-admin` | Service-principal persistence as a workspace Admin |  | EXCLUDED | Fabric-plane persistence for an SP the attacker already controls; Fabric plane not modelled (see needs_schema_data.md). |
| `az-persistence/az-fabric-persistence.md#code-and-artifact-backdoors` | Code and artifact backdoors |  | STRUCTURAL | section grouping heading |
| `az-persistence/az-fabric-persistence.md#git-integration--deployment-pipeline-supply-chain-poisoning` | Git integration & Deployment Pipeline supply-chain poisoning |  | EXCLUDED | Persistence/data-plane technique; no new Azure/Entra principal. |
| `az-persistence/az-fabric-persistence.md#custom-environment--library-persistence-databricks-init-script-analog` | Custom environment / library persistence (Databricks-init-script analog) |  | EXCLUDED | Persistence/data-plane technique; no new Azure/Entra principal. |
| `az-persistence/az-fabric-persistence.md#references` | References |  | STRUCTURAL | section grouping heading |

## az-persistence/az-firewall-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-firewall-persistence.md` |  |  | STRUCTURAL | page reviewed: persistence of an already-held foothold; identity-relevant sections mapped/excluded per heading |
| `az-persistence/az-firewall-persistence.md#pin-configuration-with-azure-policy--firewall-manager` | Pin configuration with Azure Policy / Firewall Manager | Microsoft.Authorization/policyAssignments/write,Microsoft.Authorization/roleAssignments/write,Microsoft.Network/firewallPolicies/write | EXCLUDED | Security-control weakening, telemetry tampering or DoS; no Azure/Entra principal is obtained. |
| `az-persistence/az-firewall-persistence.md#keep-diagnostic-settings-removed-or-narrowed` | Keep diagnostic settings removed or narrowed | Microsoft.Insights/diagnosticSettings/delete | EXCLUDED | Security-control weakening, telemetry tampering or DoS; no Azure/Entra principal is obtained. |
| `az-persistence/az-firewall-persistence.md#durable-allownat-rule-in-an-inherited-policy` | Durable allow/NAT rule in an inherited policy | Microsoft.Network/firewallPolicies/ruleCollectionGroups/write | EXCLUDED | Security-control weakening, telemetry tampering or DoS; no Azure/Entra principal is obtained. |

## az-persistence/az-guest-configuration-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-guest-configuration-persistence.md` |  |  | STRUCTURAL | page reviewed: persistence of an already-held foothold; identity-relevant sections mapped/excluded per heading |
| `az-persistence/az-guest-configuration-persistence.md#self-healing-persistence-via-applyandautocorrect` | Self-healing persistence via `ApplyAndAutoCorrect` | Microsoft.GuestConfiguration/guestConfigurationAssignments/write | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-guest-configuration-privesc.md#in-guest-rce-via-a-guest-configuration-assignment-marquee`, `az-privilege-escalation/az-guest-configuration-privesc.md#in-guest-rce-via-a-guest-configuration-assignment-marquee` |
| `az-persistence/az-guest-configuration-persistence.md#fleet-wide-persistence-via-azure-policy--guest-configuration` | Fleet-wide persistence via Azure Policy + guest configuration | Microsoft.Authorization/policyAssignments/write,Microsoft.Authorization/policyDefinitions/write,Microsoft.Authorization/roleAssignments/write,Microsoft.PolicyInsights/remediations/write | EXCLUDED | Per-machine Guest Configuration path NEEDS SCHEMA for exact extension, running VM, package execution, and named identity token. |

## az-persistence/az-image-builder-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-image-builder-persistence.md` |  |  | STRUCTURAL | page reviewed: persistence of an already-held foothold; identity-relevant sections mapped/excluded per heading |
| `az-persistence/az-image-builder-persistence.md#golden-image--supply-chain-persistence` | Golden-image / supply-chain persistence | Microsoft.Compute/galleries/images/versions/write,Microsoft.Compute/images/write | EXCLUDED | Strict principal-boundary audit: The source permission or capability needed to perform the stated write/action is absent from requires; reviewed target evidence alone cannot establish the X permission to Y action escalation path. |

## az-persistence/az-intune-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-intune-persistence.md` | (page) |  | STRUCTURAL | page reviewed: persistence / defense evasion: no new principal gained |
| `az-persistence/az-intune-persistence.md#az---intune-persistence` | Az - Intune Persistence |  | STRUCTURAL | title/reference/intro heading |
| `az-persistence/az-intune-persistence.md#intune` | Intune |  | EXCLUDED | persistence / defense evasion: no new principal gained |
| `az-persistence/az-intune-persistence.md#self-healing-and-protected-footholds` | Self-healing and protected footholds |  | EXCLUDED | persistence / defense evasion: no new principal gained |
| `az-persistence/az-intune-persistence.md#self-healing-persistence--defense-evasion-via-configuration-profiles` | Self-healing persistence & defense evasion via configuration profiles |  | SUBSECTION | of #self-healing-and-protected-footholds: EXCLUDED: persistence / defense evasion: no new principal gained |
| `az-persistence/az-intune-persistence.md#recurring-rce-via-proactive-remediations-persistence` | Recurring RCE via Proactive Remediations (persistence) |  | SUBSECTION | of #self-healing-and-protected-footholds: EXCLUDED: persistence / defense evasion: no new principal gained |
| `az-persistence/az-intune-persistence.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-persistence/az-key-vault-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-key-vault-persistence.md#retain-restorable-object-backups` | Retain restorable object backups |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-key-vault-persistence.md#plant-attacker-known-key-material-with-keysimport-or-keyscreate` | Plant attacker-known key material with `keys/import` (or `keys/create`) |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-key-vault-persistence.md#mint-a-new-exportable-certificate-for-appsp-credential-persistence-certificatescreate` | Mint a new exportable certificate for app/SP credential persistence (`certificates/create`) |  | EXCLUDED | Identity gain is the Entra app/SP credential add (Entra catalog); the vault step only produces certificate material. |
| `az-persistence/az-key-vault-persistence.md#resurrect-a-soft-deleted-vault-under-attacker-controlled-access-createmoderecover` | Resurrect a soft-deleted vault under attacker-controlled access (`createMode=recover`) |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-key-vault-persistence.md#backdoor-a-data-plane-principal` | Backdoor a data-plane principal |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-key-vault-persistence.md#managed-hsm-local-rbac` | Managed HSM local RBAC |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-key-vault-persistence.md#event-grid-notification-for-new-secret-versions` | Event Grid notification for new secret versions |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-key-vault-persistence.md` | Az - Key Vault Persistence |  | EXCLUDED | page reviewed: persistence techniques; rows below |

## az-persistence/az-kubernetes-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-kubernetes-persistence.md` |  |  | STRUCTURAL | page reviewed: persistence of an already-held foothold; identity-relevant sections mapped/excluded per heading |
| `az-persistence/az-kubernetes-persistence.md#flux-gitops-self-healing-foothold-fluxconfigurationswrite--sourcecontrolconfigurationswrite` | Flux GitOps self-healing foothold (`fluxConfigurations/write` / `sourceControlConfigurations/write`) | Microsoft.KubernetesConfiguration/fluxConfigurations/write | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-kubernetes-privesc.md#flux-gitops-self-healing-foothold-fluxconfigurationswrite--sourcecontrolconfigurationswrite` |
| `az-persistence/az-kubernetes-persistence.md#cluster-extension-install--privileged-in-cluster-components-extensionswrite` | Cluster extension install — privileged in-cluster components (`extensions/write`) | Microsoft.KubernetesConfiguration/extensions/write | EXCLUDED | Extension identity/permissions are extension-defined; page documents no deterministic principal gain beyond Flux (azure-aks-flux-configuration-write). |
| `az-persistence/az-kubernetes-persistence.md#re-arm-the-built-in-cluster-admin--attacker-entra-admin-group-managedclusterswrite` | Re-arm the built-in cluster admin / attacker Entra admin group (`managedClusters/write`) | Microsoft.ContainerService/managedClusters/write | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-kubernetes-privesc.md#re-arm-the-built-in-cluster-admin--graft-an-attacker-entra-admin-group-managedclusterswrite`, `az-privilege-escalation/az-kubernetes-privesc.md#re-arm-the-built-in-cluster-admin--graft-an-attacker-entra-admin-group-managedclusterswrite` |
| `az-persistence/az-kubernetes-persistence.md#reset-aad--service-principal-profile-resetaadprofile--resetserviceprincipalprofile` | Reset AAD / service-principal profile (`resetAADProfile` / `resetServicePrincipalProfile`) | Microsoft.ContainerService/managedClusters/resetAADProfile/action | EXCLUDED | Replaces the cluster's own SP/AAD profile with attacker values; persistence/DoS, no new principal for the source. |
| `az-persistence/az-kubernetes-persistence.md#related-workload-identity-federated-credential` | Related: workload-identity federated credential |  | EXCLUDED | Federated identity credential write is modelled generically by the managed-identity FIC entries (other group). |
| `az-persistence/az-kubernetes-persistence.md#trusted-access-role-binding--service-identity-access-through-the-aks-gateway-trustedaccessrolebindingswrite` | Trusted Access role binding — service identity access through the AKS gateway (`trustedAccessRoleBindings/write`) | Microsoft.ContainerService/managedClusters/trustedAccessRoleBindings/write | EXCLUDED | Grants an Azure service resource access through the AKS gateway; no principal the source controls. |

## az-persistence/az-load-testing-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-load-testing-persistence.md` |  |  | STRUCTURAL | page reviewed: persistence techniques for an already-held foothold (data-plane grants, credentials, backdoors); no new Azure/Entra principal beyond entries noted per heading |
| `az-persistence/az-load-testing-persistence.md#az---load-testing-persistence` | Az - Load Testing Persistence |  | STRUCTURAL | page title |
| `az-persistence/az-load-testing-persistence.md#load-testing` | Load Testing |  | STRUCTURAL | section grouping heading |
| `az-persistence/az-load-testing-persistence.md#references` | References |  | STRUCTURAL | section grouping heading |

## az-persistence/az-log-analytics-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-log-analytics-persistence.md#table-plan-downgrade-held-in-place-by-policy` | Table plan downgrade held in place by Policy |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-log-analytics-persistence.md#diagnostic-setting--connector-gap-that-self-heals` | Diagnostic-setting / connector gap that self-heals |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-log-analytics-persistence.md#retention-floor` | Retention floor |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-log-analytics-persistence.md#shared-key-ingestion-channel` | Shared-key ingestion channel |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-log-analytics-persistence.md` | Az - Log Analytics Persistence |  | EXCLUDED | page reviewed: persistence techniques; rows below |

## az-persistence/az-logic-apps-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-logic-apps-persistence.md` |  |  | STRUCTURAL | page reviewed: persistence of an already-held foothold; identity-relevant sections mapped/excluded per heading |
| `az-persistence/az-logic-apps-persistence.md#workflow-access-context` | Workflow access context | Microsoft.Logic/workflows/triggers/listCallbackUrl/action,Microsoft.Logic/workflows/write | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-logic-apps-privesc.md#microsoftlogicworkflowswrite` |
| `az-persistence/az-logic-apps-persistence.md#backdoored-workflow` | Backdoored workflow |  | SUBSECTION | of #workflow-access-context: MAPPED azure-logicapp-workflow-write-existing-identity |
| `az-persistence/az-logic-apps-persistence.md#inbound-oauth-authorization-policy` | Inbound OAuth authorization policy |  | SUBSECTION | of #workflow-access-context: MAPPED azure-logicapp-workflow-write-existing-identity |

## az-persistence/az-managed-applications-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-managed-applications-persistence.md#standing--cross-tenant-hidden-access-via-authorizations` | Standing / cross-tenant hidden access via `authorizations` |  | EXCLUDED | Grants access only over resources in the new managed resource group the attacker deploys; persistence (see privesc page deploy-as-identity exclusion). |
| `az-persistence/az-managed-applications-persistence.md#jit-jitrequests-eligible-role-access` | JIT (`jitRequests`) eligible-role access |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-managed-applications-persistence.md#deny-assignment-shielding-of-attacker-resources` | Deny-assignment shielding of attacker resources |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-managed-applications-persistence.md` | Az - Managed Applications Persistence |  | EXCLUDED | page reviewed: persistence techniques; rows below |

## az-persistence/az-monitor-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-monitor-persistence.md#durable-telemetry-blindness` | Durable telemetry blindness |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-monitor-persistence.md#alert-rule--action-group-as-a-trigger-you-own` | Alert-rule → Action Group as a trigger you own |  | EXCLUDED | Strict principal-boundary audit: The source permission or capability needed to perform the stated write/action is absent from requires; reviewed target evidence alone cannot establish the X permission to Y action escalation path. |
| `az-persistence/az-monitor-persistence.md#autoscale-as-a-scheduler` | Autoscale as a scheduler |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-monitor-persistence.md` | Az - Azure Monitor Persistence |  | EXCLUDED | page reviewed: persistence techniques; rows below |

## az-persistence/az-notification-hubs-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-notification-hubs-persistence.md#rogue-sas-rule-persistence-with-authorizationruleswrite` | Rogue SAS-rule persistence with `authorizationRules/write` |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-notification-hubs-persistence.md` | Az - Notification Hubs Persistence |  | EXCLUDED | page reviewed: persistence techniques; rows below |

## az-persistence/az-pim-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-pim-persistence.md` | (page) |  | STRUCTURAL | page reviewed: persistence / defense evasion: no new principal gained |
| `az-persistence/az-pim-persistence.md#az---pim-persistence` | Az - PIM Persistence |  | STRUCTURAL | title/reference/intro heading |
| `az-persistence/az-pim-persistence.md#pim` | PIM |  | EXCLUDED | persistence / defense evasion: no new principal gained |
| `az-persistence/az-pim-persistence.md#weaken-the-gate-so-activation-stays-silent` | Weaken the gate so activation stays silent |  | EXCLUDED | persistence / defense evasion: no new principal gained |
| `az-persistence/az-pim-persistence.md#standing-access-grants` | Standing access grants |  | EXCLUDED | persistence / defense evasion: no new principal gained |
| `az-persistence/az-pim-persistence.md#self-approval-loop` | Self-approval loop |  | SUBSECTION | of #standing-access-grants: EXCLUDED: persistence / defense evasion: no new principal gained |
| `az-persistence/az-pim-persistence.md#plant-eligible-assignments` | Plant eligible assignments |  | SUBSECTION | of #standing-access-grants: EXCLUDED: persistence / defense evasion: no new principal gained |
| `az-persistence/az-pim-persistence.md#pim-for-groups-as-durable-indirect-privilege` | PIM for Groups as durable, indirect privilege |  | SUBSECTION | of #standing-access-grants: EXCLUDED: persistence / defense evasion: no new principal gained |
| `az-persistence/az-pim-persistence.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-persistence/az-policy-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-policy-persistence.md#self-healing-configuration-backdoors` | Self-healing configuration backdoors |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-policy-persistence.md#self-healing-role-grant-the-headline-technique` | Self-healing role grant (the headline technique) |  | EXCLUDED | Persistence; requires roleAssignments/write (azure-authorization-roleassignments-write) for the remediation identity. |
| `az-persistence/az-policy-persistence.md` | Az - Azure Policy Persistence |  | EXCLUDED | page reviewed: persistence techniques; rows below |

## az-persistence/az-purview-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-purview-persistence.md` |  |  | STRUCTURAL | page reviewed: persistence techniques for an already-held foothold (data-plane grants, credentials, backdoors); no new Azure/Entra principal beyond entries noted per heading |
| `az-persistence/az-purview-persistence.md#az---purview-persistence` | Az - Purview Persistence |  | STRUCTURAL | page title |
| `az-persistence/az-purview-persistence.md#purview` | Purview |  | STRUCTURAL | section grouping heading |
| `az-persistence/az-purview-persistence.md#standing-access-grants` | Standing access grants |  | STRUCTURAL | section grouping heading |
| `az-persistence/az-purview-persistence.md#over-privileged-scanning-identity-retained` | Over-privileged scanning identity retained |  | EXCLUDED | Persistence/data-plane technique; no new Azure/Entra principal. |
| `az-persistence/az-purview-persistence.md#self-service-access-workflow-auto-approval` | Self-service-access workflow auto-approval |  | EXCLUDED | Persistence/data-plane technique; no new Azure/Entra principal. |
| `az-persistence/az-purview-persistence.md#collection-role-foothold` | Collection-role foothold |  | EXCLUDED | Persistence/data-plane technique; no new Azure/Entra principal. |
| `az-persistence/az-purview-persistence.md#blindness-that-self-sustains` | Blindness that self-sustains |  | EXCLUDED | Persistence/data-plane technique; no new Azure/Entra principal. |
| `az-persistence/az-purview-persistence.md#reusable-credentials` | Reusable credentials |  | STRUCTURAL | section grouping heading |
| `az-persistence/az-purview-persistence.md#rogue-self-hosted-integration-runtime-as-a-credential-relay` | Rogue self-hosted integration runtime as a credential relay |  | EXCLUDED | Strict principal-boundary audit: The credential_stored_in_scope selector has no exact usable credential and identified target-principal evidence enforcement for this technique; a secret read or arbitrary configuration change alone is not an established principal escalation. |
| `az-persistence/az-purview-persistence.md#long-lived-event-hubs-channel-via-listkeys` | Long-lived Event Hubs channel via `listkeys` | Microsoft.Purview/accounts/listkeys/action | EXCLUDED | Persistence/data-plane technique; no new Azure/Entra principal. |
| `az-persistence/az-purview-persistence.md#references` | References |  | STRUCTURAL | section grouping heading |

## az-persistence/az-redis-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-redis-persistence.md#key-independent-persistence-with-microsoftcacheredisaccesspolicyassignmentswrite` | Key-independent persistence with `Microsoft.Cache/redis/accessPolicyAssignments/write` | Microsoft.Cache/redis/accessPolicyAssignments/write | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-redis-persistence.md#continuous-exfil--persistence-with-microsoftcacheredislinkedserverswrite` | Continuous exfil + persistence with `Microsoft.Cache/redis/linkedServers/write` | Microsoft.Cache/redis/linkedServers/write | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-redis-persistence.md` | Az - Redis Persistence |  | EXCLUDED | page reviewed: persistence techniques; rows below |

## az-persistence/az-relay-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-relay-persistence.md#rogue-sas-rule-persistence-with-authorizationruleswrite` | Rogue SAS-rule persistence with `authorizationRules/write` |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-relay-persistence.md#unauthenticated-tunnel-with-hybridconnectionswrite` | Unauthenticated tunnel with `HybridConnections/write` |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-relay-persistence.md` | Az - Relay Persistence |  | EXCLUDED | page reviewed: persistence techniques; rows below |

## az-persistence/az-sentinel-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-sentinel-persistence.md#standing-auto-close-automation-rule` | Standing auto-close automation rule |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-sentinel-persistence.md#analytics-rule-tampering-that-survives-review` | Analytics-rule tampering that survives review |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-sentinel-persistence.md#watchlist-as-an-allow-list-backdoor` | Watchlist as an allow-list backdoor |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-sentinel-persistence.md#connector--ingestion-gap-held-in-place` | Connector / ingestion gap held in place |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-sentinel-persistence.md` | Az - Sentinel Persistence |  | EXCLUDED | page reviewed: persistence techniques; rows below |

## az-persistence/az-service-fabric-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-service-fabric-persistence.md` |  |  | STRUCTURAL | page reviewed: persistence of an already-held foothold; identity-relevant sections mapped/excluded per heading |

## az-persistence/az-servicebus-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-servicebus-persistence.md#self-minted-sas-authorization-rule-entra-independent-bearer-credential` | Self-minted SAS authorization rule (Entra-independent bearer credential) |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-servicebus-persistence.md#durable-copy-through-a-new-topic-subscription` | Durable copy through a new topic subscription |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-servicebus-persistence.md` | Az - Service Bus Persistence |  | EXCLUDED | page reviewed: persistence techniques; rows below |

## az-persistence/az-spring-apps-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-spring-apps-persistence.md` |  |  | STRUCTURAL | page reviewed: persistence of an already-held foothold; identity-relevant sections mapped/excluded per heading |
| `az-persistence/az-spring-apps-persistence.md#code-and-artifact-backdoors` | Code and artifact backdoors |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-spring-apps-privesc.md#app-deploy-rce--managed-identity-theft-marquee` |

## az-persistence/az-sql-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-sql-persistence.md` |  |  | STRUCTURAL | page reviewed: persistence techniques for an already-held foothold (data-plane grants, credentials, backdoors); no new Azure/Entra principal beyond entries noted per heading; SQL MI admin parity added as azure-sqlmi-entra-admin-write, azure-sqlmi-admin-password-reset |
| `az-persistence/az-sql-persistence.md#az---sql-persistence` | Az - SQL Persistence |  | STRUCTURAL | page title |
| `az-persistence/az-sql-persistence.md#sql` | SQL |  | STRUCTURAL | section grouping heading |
| `az-persistence/az-sql-persistence.md#server-dns-alias-hijack-microsoftsqlserversdnsaliasesacquireaction` | Server DNS alias hijack (`Microsoft.Sql/servers/dnsAliases/acquire/action`) | Microsoft.Sql/servers/dnsAliases/acquire/action,Microsoft.Sql/servers/dnsAliases/write | EXCLUDED | Persistence/data-plane technique; no new Azure/Entra principal. |
| `az-persistence/az-sql-persistence.md#tde-protector-repoint-kill-switch-microsoftsqlserversencryptionprotectorwrite` | TDE-protector repoint kill-switch (`Microsoft.Sql/servers/encryptionProtector/write`) | Microsoft.Sql/managedInstances/keys/write,Microsoft.Sql/servers/encryptionProtector/write | EXCLUDED | Persistence/data-plane technique; no new Azure/Entra principal. |
| `az-persistence/az-sql-persistence.md#sql-managed-instance-parity-and-clr-based-persistence` | SQL Managed Instance parity and CLR-based persistence | Microsoft.Sql/managedInstances/administrators/write | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-sql-privesc.md#sql-managed-instance-parity-and-clr-based-persistence`, `az-privilege-escalation/az-sql-privesc.md#sql-managed-instance-parity-and-clr-based-persistence` |
| `az-persistence/az-sql-persistence.md#database-access-context` | Database access context | Microsoft.Sql/servers/administrators/write,Microsoft.Sql/servers/firewallRules/write | EXCLUDED | Persistence/data-plane technique; no new Azure/Entra principal. |
| `az-persistence/az-sql-persistence.md#sql-authentication-credentials` | SQL authentication credentials |  | EXCLUDED | Persistence/data-plane technique; no new Azure/Entra principal. |
| `az-persistence/az-sql-persistence.md#standing-access-grants` | Standing access grants |  | STRUCTURAL | section grouping heading |
| `az-persistence/az-sql-persistence.md#microsoft-entra-administrator` | Microsoft Entra administrator |  | EXCLUDED | Persistence/data-plane technique; no new Azure/Entra principal. |
| `az-persistence/az-sql-persistence.md#firewall-rules` | Firewall rules |  | EXCLUDED | Persistence/data-plane technique; no new Azure/Entra principal. |
| `az-persistence/az-sql-persistence.md#guest-os-persistence-on-sql-server-vms` | Guest-OS persistence on SQL Server VMs |  | EXCLUDED | VM guest-OS persistence; VM identity paths are covered by compute entries. |
| `az-persistence/az-sql-persistence.md#references` | References |  | STRUCTURAL | section grouping heading |

## az-persistence/az-storage-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-storage-persistence.md#retain-storage-account-access-keys` | Retain storage account access keys |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-storage-persistence.md#long-lived-sas-tokens` | Long-lived SAS tokens |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-storage-persistence.md#sftp-local-users-a-credential-outside-entra-id` | SFTP local users: a credential outside Entra ID |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-storage-persistence.md#stored-access-policy-backdoor-re-mintable-expiry-less-sas` | Stored access policy backdoor (re-mintable, expiry-less SAS) |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-storage-persistence.md#object-replication-continuous-automatic-exfiltration` | Object replication: continuous automatic exfiltration |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-storage-persistence.md#event-grid-subscription-live-notification-of-every-new-blob` | Event Grid subscription: live notification of every new blob |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-storage-persistence.md#wildcard-cors-rule-a-durable-browser-driven-exfiltration-channel` | Wildcard CORS rule: a durable browser-driven exfiltration channel |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-storage-persistence.md#lifecycle-management-policy-destroy-data-without-any-delete-permission` | Lifecycle management policy: destroy data without any delete permission |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-storage-persistence.md#static-website-hosting-on-a-trusted-microsoft-domain` | Static website hosting on a trusted Microsoft domain |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-storage-persistence.md#soft-delete--retention-as-attacker-controlled-data-retention` | Soft delete / retention as attacker-controlled data retention |  | EXCLUDED | Persistence of already-held access or data-plane credentials; no other principal's privileges (rule 4). |
| `az-persistence/az-storage-persistence.md` | Az - Storage Persistence |  | EXCLUDED | page reviewed: persistence techniques; rows below |

## az-persistence/az-virtual-desktop-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-virtual-desktop-persistence.md` |  |  | STRUCTURAL | page reviewed: persistence of an already-held foothold; identity-relevant sections mapped/excluded per heading |
| `az-persistence/az-virtual-desktop-persistence.md#fslogix-profile-and-session-host-implants` | FSLogix profile and session-host implants |  | EXCLUDED | Implants in profile containers/session hosts already controlled; users' later sessions are content/behaviour-dependent and not RBAC-derivable. |

## az-persistence/az-vms-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-vms-persistence.md` |  |  | STRUCTURAL | page reviewed: persistence of an already-held foothold; identity-relevant sections mapped/excluded per heading |
| `az-persistence/az-vms-persistence.md#backdoor-vm-applications-vm-extensions--images` | Backdoor VM applications, VM Extensions & Images <a href="#backdoor-vm-applications-vm-extensions-images" id="backdoor-vm-applications-vm-extensions-images"></a> | Microsoft.Compute/galleries/applications/versions/write | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputegallerieswrite-microsoftcomputegalleriesapplicationswrite-microsoftcomputegalleriesapplicationsversionswrite-microsoftcomputevirtualmachineswrite`, `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputevirtualmachinesextensionswrite` |
| `az-persistence/az-vms-persistence.md#backdoor-instances` | Backdoor Instances <a href="#backdoor-instances" id="backdoor-instances"></a> |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputevirtualmachinesextensionswrite` |
| `az-persistence/az-vms-persistence.md#reimage--redeploy-to-re-execute-poisoned-customdata` | Reimage / redeploy to re-execute poisoned `customData` | Microsoft.Compute/virtualMachines/reimage/action,Microsoft.Compute/virtualMachines/write | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#reimage--redeploy-to-re-execute-poisoned-customdata` |
| `az-persistence/az-vms-persistence.md#attach-a-public-ip--lb-nat-rule-to-a-private-vm-durable-reachability` | Attach a Public IP / LB NAT rule to a private VM (durable reachability) | Microsoft.Network/loadBalancers/write,Microsoft.Network/networkInterfaces/write,Microsoft.Network/publicIPAddresses/join/action,Microsoft.Network/publicIPAddresses/write | EXCLUDED | Network/traffic interception, exposure or DNS tampering; no Azure/Entra principal is obtained. |

## az-persistence/az-vmware-solution-avs-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-vmware-solution-avs-persistence.md` |  |  | STRUCTURAL | page reviewed: persistence of an already-held foothold; identity-relevant sections mapped/excluded per heading |
| `az-persistence/az-vmware-solution-avs-persistence.md#credential-rotation-persistence--lockout-rotatepassword` | Credential-rotation persistence & lockout (`rotate*Password`) | Microsoft.AVS/privateClouds/rotateNsxtCloudAdminPassword/action,Microsoft.AVS/privateClouds/rotateNsxtPassword/action,Microsoft.AVS/privateClouds/rotateVcenterPassword/action | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-vmware-solution-avs-privesc.md#cloudadmin--nsx-t-credential-disclosure-listadmincredentials` |
| `az-persistence/az-vmware-solution-avs-persistence.md#network-path-persistence-authorizationswrite-addonswrite` | Network-path persistence (`authorizations/write`, `addOns/write`) | Microsoft.AVS/privateClouds/addOns/write,Microsoft.AVS/privateClouds/authorizations/write | EXCLUDED | Network/traffic interception, exposure or DNS tampering; no Azure/Entra principal is obtained. |

## az-persistence/az-waf-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-waf-persistence.md` |  |  | STRUCTURAL | page reviewed: persistence of an already-held foothold; identity-relevant sections mapped/excluded per heading |
| `az-persistence/az-waf-persistence.md#policy-shared-across-many-endpoints` | Policy shared across many endpoints | Microsoft.Network/*WebApplicationFirewallPolicies/write | EXCLUDED | Security-control weakening, telemetry tampering or DoS; no Azure/Entra principal is obtained. |
| `az-persistence/az-waf-persistence.md#standing-custom-allow-rule--exclusion` | Standing custom allow rule / exclusion | Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/write,Microsoft.Network/frontdoorWebApplicationFirewallPolicies/write | EXCLUDED | Security-control weakening, telemetry tampering or DoS; no Azure/Entra principal is obtained. |
| `az-persistence/az-waf-persistence.md#pin-it-with-azure-policy` | Pin it with Azure Policy | Microsoft.Authorization/policyAssignments/write,Microsoft.Authorization/roleAssignments/write | EXCLUDED | Security-control weakening, telemetry tampering or DoS; no Azure/Entra principal is obtained. |
| `az-persistence/az-waf-persistence.md#keep-diagnostic-settings-removed-or-narrowed` | Keep diagnostic settings removed or narrowed | Microsoft.Insights/diagnosticSettings/delete | EXCLUDED | Security-control weakening, telemetry tampering or DoS; no Azure/Entra principal is obtained. |

## az-post-exploitation/az-advisor-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-advisor-post-exploitation.md#advisor-as-a-recon-oracle` | Advisor as a recon oracle |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-advisor-post-exploitation.md#suppressing-the-findings-you-create` | Suppressing the findings you create |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-advisor-post-exploitation.md#excluding-the-whole-scope-from-advisor` | Excluding the whole scope from Advisor |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-advisor-post-exploitation.md#dosbreak` | DoS/Break |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-advisor-post-exploitation.md` | Az - Advisor Post Exploitation |  | EXCLUDED | page reviewed: post-exploitation techniques; rows below |

## az-post-exploitation/az-analysis-services-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-analysis-services-post-exploitation.md` |  |  | STRUCTURAL | page reviewed: data exfiltration, tampering, evasion and DoS; identity-relevant sections are covered by existing entries or excluded below |
| `az-post-exploitation/az-analysis-services-post-exploitation.md#az---analysis-services-post-exploitation` | Az - Analysis Services Post Exploitation |  | STRUCTURAL | page title |
| `az-post-exploitation/az-analysis-services-post-exploitation.md#analysis-services` | Analysis Services |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-analysis-services-post-exploitation.md#dosbreak` | DoS/Break |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-analysis-services-post-exploitation.md#suspend--resume--delete-availability--cost` | Suspend / resume / delete (availability & cost) |  | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-analysis-services-post-exploitation.md#references` | References |  | STRUCTURAL | section grouping heading |

## az-post-exploitation/az-api-management-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-api-management-post-exploitation.md` |  |  | STRUCTURAL | page reviewed: data exfiltration, tampering, evasion and DoS; identity-relevant sections mapped/excluded per heading |
| `az-post-exploitation/az-api-management-post-exploitation.md#microsoftapimanagementservicegatewaysgetconfigurationaction--bulk-policysecret-pull-data-action-bypasses-the-administrative-log` | `Microsoft.ApiManagement/service/gateways/getConfiguration/action` — bulk policy/secret pull (data action, bypasses the Administrative log) | Microsoft.ApiManagement/service/gateways/getConfiguration/action | EXCLUDED | Self-hosted gateway configuration/secrets of unknown content; no Azure/Entra principal. |
| `az-post-exploitation/az-api-management-post-exploitation.md#microsoftapimanagementservicegatewayslistkeysaction--raw-self-hosted-gateway-keys-offline-token-minting` | `Microsoft.ApiManagement/service/gateways/listKeys/action` — raw self-hosted-gateway keys (offline token minting) | Microsoft.ApiManagement/service/gateways/listKeys/action | EXCLUDED | NEEDS SCHEMA: the returned key may authenticate a self-hosted APIM gateway identity, but exact gateway subject, usable credential, new operation, and prior-absence proof are not verified. |
| `az-post-exploitation/az-api-management-post-exploitation.md#microsoftapimanagementservicebackupaction--full-service-exfiltration-to-attacker-storage` | `Microsoft.ApiManagement/service/backup/action` — full-service exfiltration to attacker storage | Microsoft.ApiManagement/service/backup/action | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-api-management-privesc.md#microsoftapimanagementservicebackupaction--full-service-exfiltration-to-attacker-storage` |
| `az-post-exploitation/az-api-management-post-exploitation.md#microsoftapimanagementservicegatewayslistdebugcredentialsaction--servicegatewayslisttraceaction--live-requestresponse-wiretap` | `Microsoft.ApiManagement/service/gateways/listDebugCredentials/action` + `service/gateways/listTrace/action` — live request/response wiretap | Microsoft.ApiManagement/service/gateways/listDebugCredentials/action | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-api-management-privesc.md#microsoftapimanagementservicegatewayslistdebugcredentialsaction--servicegatewayslisttraceaction--live-requestresponse-wiretap` |
| `az-post-exploitation/az-api-management-post-exploitation.md#microsoftapimanagementservicetenantdeployaction--bulk-config-overwrite-via-built-in-git` | `Microsoft.ApiManagement/service/tenant/deploy/action` — bulk config overwrite via built-in Git | Microsoft.ApiManagement/service/tenant/deploy/action | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-api-management-privesc.md#microsoftapimanagementservicetenantdeployaction--bulk-config-overwrite-via-built-in-git` |
| `az-post-exploitation/az-api-management-post-exploitation.md#microsoftapimanagementserviceloggerswrite--servicediagnosticswrite--persistent-traffic-exfil-to-attacker-event-hub` | `Microsoft.ApiManagement/service/loggers/write` + `service/diagnostics/write` — persistent traffic exfil to attacker Event Hub | Microsoft.ApiManagement/service/loggers/write | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-api-management-privesc.md#microsoftapimanagementserviceloggerswrite--servicediagnosticswrite--persistent-traffic-exfil-to-attacker-event-hub` |
| `az-post-exploitation/az-api-management-post-exploitation.md#microsoftapimanagementserviceapispolicieswrite-or-microsoftapimanagementservicepolicieswrite` | `Microsoft.ApiManagement/service/apis/policies/write` or `Microsoft.ApiManagement/service/policies/write` | Microsoft.ApiManagement/service/apis/policies/write,Microsoft.ApiManagement/service/policies/write | EXCLUDED | Security-control weakening, telemetry tampering or DoS; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-api-management-post-exploitation.md#microsoftapimanagementservicebackendswrite-or-microsoftapimanagementservicebackendsdelete` | `Microsoft.ApiManagement/service/backends/write` or `Microsoft.ApiManagement/service/backends/delete` | Microsoft.ApiManagement/service/backends/delete,Microsoft.ApiManagement/service/backends/write | EXCLUDED | Security-control weakening, telemetry tampering or DoS; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-api-management-post-exploitation.md#microsoftapimanagementserviceapisdelete` | `Microsoft.ApiManagement/service/apis/delete` | Microsoft.ApiManagement/service/apis/delete | EXCLUDED | Security-control weakening, telemetry tampering or DoS; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-api-management-post-exploitation.md#microsoftapimanagementservicewrite` | `Microsoft.ApiManagement/service/write` | Microsoft.ApiManagement/service/write | EXCLUDED | Security-control weakening, telemetry tampering or DoS; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-api-management-post-exploitation.md#microsoftapimanagementservicesubscriptionsdelete` | `Microsoft.ApiManagement/service/subscriptions/delete` | Microsoft.ApiManagement/service/subscriptions/delete | EXCLUDED | Security-control weakening, telemetry tampering or DoS; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-api-management-post-exploitation.md#microsoftapimanagementservicebackendsread` | `Microsoft.ApiManagement/service/backends/read` | Microsoft.ApiManagement/service/backends/read | EXCLUDED | Stored header credentials of unknown content; data read. |
| `az-post-exploitation/az-api-management-post-exploitation.md#policy-read-permissions` | Policy read permissions | Microsoft.ApiManagement/service/apis/operations/policies/read,Microsoft.ApiManagement/service/apis/policies/read,Microsoft.ApiManagement/service/policies/read,Microsoft.ApiManagement/service/products/policies/read | EXCLUDED | Data read of embedded values. |
| `az-post-exploitation/az-api-management-post-exploitation.md#network-configuration` | Network configuration |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-api-management-post-exploitation.md#microsoftapimanagementserviceapplynetworkconfigurationupdatesaction` | `Microsoft.ApiManagement/service/applynetworkconfigurationupdates/action` | Microsoft.ApiManagement/service/applynetworkconfigurationupdates/action,Microsoft.ApiManagement/service/write | EXCLUDED | Network exposure change only. |

## az-post-exploitation/az-app-configuration-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-app-configuration-post-exploitation.md#bulk-exfil--loot-persistence-via-snapshots-configurationstoressnapshotsread--write` | Bulk exfil & loot-persistence via snapshots (`configurationStores/snapshots/read` / `write`) |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-app-configuration-post-exploitation.md#delete-and-purge-the-store` | Delete and purge the store |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-app-configuration-post-exploitation.md` | Az - App Configuration Post Exploitation |  | EXCLUDED | page reviewed: post-exploitation techniques; rows below |
| `az-post-exploitation/az-app-configuration-post-exploitation.md#read-one-key-value` | Read one key-value |  | STRUCTURAL | section grouping heading for the two read sub-techniques (both excluded) |
| `az-post-exploitation/az-app-configuration-post-exploitation.md#microsoftappconfigurationconfigurationstoreslistkeyvalueaction` | Microsoft.AppConfiguration/configurationStores/ListKeyValue/action | Microsoft.AppConfiguration/configurationStores/ListKeyValue/action | EXCLUDED | Data read of configuration values; Key Vault references resolve only with the consumer's identity, so no Azure identity is gained by the source. |
| `az-post-exploitation/az-app-configuration-post-exploitation.md#microsoftappconfigurationconfigurationstoreskeyvaluesread` | Microsoft.AppConfiguration/configurationStores/keyValues/read | Microsoft.AppConfiguration/configurationStores/keyValues/read | EXCLUDED | Data read; no identity gained. |

## az-post-exploitation/az-automation-accounts-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-automation-accounts-post-exploitation.md#steal-the-accounts-managed-identity-token` | Steal the account's managed identity token |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-automation-accounts-privesc.md#microsoftautomationautomationaccountsjobswrite-microsoftautomationautomationaccountsrunbooksdraftwrite-microsoftautomationautomationaccountsrunbooksdraftcontentwrite-microsoftautomationautomationaccountsjobsoutputread-microsoftautomationautomationaccountsrunbookspublishaction-microsoftresourcessubscriptionsresourcegroupsread-microsoftautomationautomationaccountsrunbookswrite` |
| `az-post-exploitation/az-automation-accounts-post-exploitation.md#dump-encrypted-variables-and-stored-credentials` | Dump encrypted variables and stored credentials |  | EXCLUDED | Strict principal-boundary audit: The credential asset contents and target principal are unknown; the entry explicitly proposes an aggregate conditional node without a verified usable credential. |
| `az-post-exploitation/az-automation-accounts-post-exploitation.md#harvest-secrets-from-prior-job-output-and-streams` | Harvest secrets from prior job output and streams |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-automation-accounts-post-exploitation.md#read-runbook-source-for-hardcoded-secrets` | Read runbook source for hardcoded secrets |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-automation-accounts-post-exploitation.md#enumerate-connections-and-other-assets` | Enumerate connections and other assets |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-automation-accounts-post-exploitation.md#dosbreak` | DoS/Break |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-automation-accounts-post-exploitation.md` | Az - Automation Accounts Post Exploitation |  | EXCLUDED | page reviewed: post-exploitation techniques; rows below |
| `az-post-exploitation/az-automation-accounts-post-exploitation.md#microsoftautomationautomationaccountsjobsstreamsread` | `Microsoft.Automation/automationAccounts/jobs/streams/read` | Microsoft.Automation/automationAccounts/jobs/streams/read | EXCLUDED | Data read of historical job output; any secret exposure is content-dependent (Exposure/Least Privilege). |
| `az-post-exploitation/az-automation-accounts-post-exploitation.md#microsoftautomationautomationaccountsvariablesread` | `Microsoft.Automation/automationAccounts/variables/read` | Microsoft.Automation/automationAccounts/variables/read | EXCLUDED | Data read of unencrypted variables only (encrypted values return null); content-dependent exposure. |

## az-post-exploitation/az-azure-ai-foundry-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-azure-ai-foundry-post-exploitation.md` |  |  | STRUCTURAL | page reviewed: data exfiltration, tampering, evasion and DoS; identity-relevant sections are covered by existing entries or excluded below |
| `az-post-exploitation/az-azure-ai-foundry-post-exploitation.md#azure---ai-foundry-post-exploitation-via-hugging-face-model-namespace-reuse` | Azure - AI Foundry Post-Exploitation via Hugging Face Model Namespace Reuse |  | STRUCTURAL | page title |
| `az-post-exploitation/az-azure-ai-foundry-post-exploitation.md#ai-foundry-ai-hubs-azure-openai--ai-search` | AI Foundry, AI Hubs, Azure OpenAI & AI Search |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-azure-ai-foundry-post-exploitation.md#identifying-reusable-namespaces-hf` | Identifying Reusable Namespaces (HF) |  | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-azure-ai-foundry-post-exploitation.md#recognition-heuristics-http` | Recognition Heuristics (HTTP) |  | STRUCTURAL | how-to subheading |
| `az-post-exploitation/az-azure-ai-foundry-post-exploitation.md#credential-access` | Credential access |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-azure-ai-foundry-post-exploitation.md#recover-managed-identity-tokens-from-an-azure-endpoint` | Recover managed-identity tokens from an Azure endpoint |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-ai-foundry-privesc.md#microsoftmachinelearningservicesworkspacesonlineendpointswrite-microsoftmachinelearningservicesworkspacesonlineendpointsdeploymentswrite-microsoftmachinelearningservicesworkspacesread`, `az-privilege-escalation/az-ai-foundry-privesc.md#microsoftmachinelearningservicesworkspacesonlineendpointswrite-microsoftmachinelearningservicesworkspacesonlineendpointsdeploymentswrite-microsoftmachinelearningservicesworkspacesread` |
| `az-post-exploitation/az-azure-ai-foundry-post-exploitation.md#data-tampering` | Data tampering |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-azure-ai-foundry-post-exploitation.md#poison-a-reused-hugging-face-model-namespace` | Poison a reused Hugging Face model namespace | Microsoft.MachineLearningServices/workspaces/onlineEndpoints/*/write | EXCLUDED | External supply-chain (HF namespace re-registration); identity gain is the endpoint MI already modelled by azure-ml-online-* entries. |
| `az-post-exploitation/az-azure-ai-foundry-post-exploitation.md#notes` | Notes |  | STRUCTURAL | how-to subheading |
| `az-post-exploitation/az-azure-ai-foundry-post-exploitation.md#other-configuration-abuse` | Other configuration abuse |  | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-azure-ai-foundry-post-exploitation.md#security-control-bypass` | Security control bypass |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-azure-ai-foundry-post-exploitation.md#model-guardrail-tampering` | Model guardrail tampering |  | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-azure-ai-foundry-post-exploitation.md#microsoftcognitiveservicesaccountsraipolicieswrite--deploymentswrite--disable-content-filters--prompt-injection-shields` | `Microsoft.CognitiveServices/accounts/raiPolicies/write` (+ `deployments/write`) — disable content filters / prompt-injection shields | Microsoft.CognitiveServices/accounts/raiPolicies/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-azure-ai-foundry-post-exploitation.md#telemetry-tampering` | Telemetry tampering |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-azure-ai-foundry-post-exploitation.md#microsoftcognitiveservicesaccountsdefenderforaisettingswrite--disable-defender-for-ai-detection-evasion` | `Microsoft.CognitiveServices/accounts/defenderForAISettings/write` — disable Defender for AI (detection evasion) | Microsoft.CognitiveServices/accounts/defenderForAISettings/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-azure-ai-foundry-post-exploitation.md#dosbreak` | DoS/Break |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-azure-ai-foundry-post-exploitation.md#microsoftcognitiveservicesaccountsdeploymentswrite--deploy-a-model-cost-abuse--inference-surface-creation` | `Microsoft.CognitiveServices/accounts/deployments/write` — deploy a model (cost abuse + inference-surface creation) | Microsoft.CognitiveServices/accounts/deployments/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-azure-ai-foundry-post-exploitation.md#cross-references` | Cross-References |  | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-azure-ai-foundry-post-exploitation.md#references` | References |  | STRUCTURAL | section grouping heading |

## az-post-exploitation/az-backup-and-recovery-services-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-backup-and-recovery-services-post-exploitation.md#retain-a-generated-vault-credential--register-a-rogue-agent` | Retain a generated vault credential / register a rogue agent |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-backup-and-recovery-services-post-exploitation.md#restore-vm--disks-to-attacker-rg-or-subscription` | Restore VM / disks to attacker RG or subscription |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-backup-and-recovery-services-post-exploitation.md#instant-item-level-recovery-quietest-exfil` | Instant Item-Level Recovery (quietest exfil) |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-backup-and-recovery-services-post-exploitation.md#sql--sap-hana--azure-files--blob-restore` | SQL / SAP HANA / Azure Files / Blob restore |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-backup-and-recovery-services-post-exploitation.md#cross-region-restore-read-from-the-paired-secondary-region` | Cross-Region Restore (read from the paired secondary region) |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-backup-and-recovery-services-post-exploitation.md#cross-tenant-vault-mapping--vaultcredentialsgenerate-exfil-across-a-tenant-boundary` | Cross-tenant vault mapping + `vaultCredentials/generate` (exfil across a tenant boundary) |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-backup-and-recovery-services-post-exploitation.md#azure-site-recovery--clone-or-disrupt-a-protected-vm` | Azure Site Recovery — clone or disrupt a protected VM |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-backup-and-recovery-services-post-exploitation.md#remove--unlock-the-resource-guard-strip-mua` | Remove / unlock the Resource Guard (strip MUA) |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-backup-and-recovery-services-post-exploitation.md#stop-protection-with-delete-data` | Stop protection with delete data |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-backup-and-recovery-services-post-exploitation.md#disable-soft-delete--weaken-security-config` | Disable soft delete / weaken security config |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-backup-and-recovery-services-post-exploitation.md#reduce-retention--delete-policy-downgrade-redundancy-get-security-pin-disable-immutability` | Reduce retention / delete policy, downgrade redundancy, get security PIN, disable immutability |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-backup-and-recovery-services-post-exploitation.md` | Az - Backup & Recovery Services Post-Exploitation |  | EXCLUDED | page reviewed: post-exploitation techniques; rows below |

## az-post-exploitation/az-batch-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-batch-post-exploitation.md` |  |  | STRUCTURAL | page reviewed: data exfiltration, tampering, evasion and DoS; identity-relevant sections mapped/excluded per heading |
| `az-post-exploitation/az-batch-post-exploitation.md#telemetry-tampering` | Telemetry tampering | Microsoft.Batch/batchAccounts/providers/Microsoft.Insights/diagnosticSettings/write | EXCLUDED | Security-control weakening, telemetry tampering or DoS; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-batch-post-exploitation.md#dosbreak` | DoS/Break |  | EXCLUDED | Security-control weakening, telemetry tampering or DoS; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-batch-post-exploitation.md#read-plaintext-job-and-schedule-configuration` | Read plaintext job and schedule configuration | Microsoft.Batch/batchAccounts/jobSchedules/read,Microsoft.Batch/batchAccounts/jobs/read | EXCLUDED | Data read of configuration of unknown content. |

## az-post-exploitation/az-blob-storage-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-blob-storage-post-exploitation.md#microsoftstoragestorageaccountsblobservicescontainersblobsread` | `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read` | Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-blob-storage-post-exploitation.md#blob-inventory-report-full-object-catalog-without-readlist` | Blob inventory report: full object catalog without `read`/`list` |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-blob-storage-post-exploitation.md#microsoftstoragestorageaccountsblobservicescontainersblobswrite` | `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write` | Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-blob-storage-post-exploitation.md#storage-account-name-takeover-of-diagnostic-exports` | Storage account name takeover of diagnostic exports |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-blob-storage-post-exploitation.md#delete` | \*/delete |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-blob-storage-post-exploitation.md#account-wide-cmk-ransomware-repoint-keyvaultproperties-to-an-attacker-key` | Account-wide CMK ransomware: repoint `keyVaultProperties` to an attacker key |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-blob-storage-post-exploitation.md#surgical-ransomware-with-encryptionscopeswrite--attacker-cmk` | Surgical ransomware with `encryptionScopes/write` + attacker CMK |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-blob-storage-post-exploitation.md#anti-forensics-disable-versioning-change-feed-and-soft-delete-before-a-wipe` | Anti-forensics: disable versioning, change feed and soft delete before a wipe |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-blob-storage-post-exploitation.md#account-failover-as-dos--data-loss-storageaccountsfailoveraction` | Account failover as DoS / data loss (`storageAccounts/failover/action`) |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-blob-storage-post-exploitation.md#lifecycle-tier-to-archive-delayed-availability--cost-dos` | Lifecycle tier-to-Archive: delayed availability & cost DoS |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-blob-storage-post-exploitation.md` | Az - Blob Storage Post Exploitation |  | EXCLUDED | page reviewed: post-exploitation techniques; rows below |

## az-post-exploitation/az-bot-service-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-bot-service-post-exploitation.md` |  |  | STRUCTURAL | page reviewed: data exfiltration, tampering, evasion and DoS; identity-relevant sections are covered by existing entries or excluded below |
| `az-post-exploitation/az-bot-service-post-exploitation.md#az---bot-service-post-exploitation` | Az - Bot Service Post Exploitation |  | STRUCTURAL | page title |
| `az-post-exploitation/az-bot-service-post-exploitation.md#azure-bot-service` | Azure Bot Service |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-bot-service-post-exploitation.md#data-export` | Data export |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-bot-service-post-exploitation.md#microsofthealthbothealthbotsadminconversationlogsexportaction` | `Microsoft.HealthBot/healthBots/Admin/ConversationLogs/Export/Action` | Microsoft.HealthBot/healthBots/Admin/ConversationLogs/Export/Action | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-bot-service-post-exploitation.md#references` | References |  | STRUCTURAL | section grouping heading |

## az-post-exploitation/az-chaos-studio-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-chaos-studio-post-exploitation.md` |  |  | STRUCTURAL | page reviewed: data exfiltration, tampering, evasion and DoS; identity-relevant sections mapped/excluded per heading |
| `az-post-exploitation/az-chaos-studio-post-exploitation.md#cancel--suppress-a-defenders-remediation-drill` | Cancel / suppress a defender's remediation drill | Microsoft.Chaos/experiments/cancel/action | EXCLUDED | Fault injection/telemetry tampering; the experiment identity token is not handed to the caller. |
| `az-post-exploitation/az-chaos-studio-post-exploitation.md#detonate-faults-against-onboarded-targets-availability-attack` | Detonate faults against onboarded targets (availability attack) |  | EXCLUDED | Fault injection/telemetry tampering; the experiment identity token is not handed to the caller. |

## az-post-exploitation/az-cloud-shell-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-cloud-shell-post-exploitation.md` |  |  | STRUCTURAL | page reviewed: data exfiltration, tampering, evasion and DoS; identity-relevant sections mapped/excluded per heading |
| `az-post-exploitation/az-cloud-shell-post-exploitation.md#cloud-shell` | Cloud Shell |  | EXCLUDED | In-session $MSI_ENDPOINT token use is the caller's own identity (on-box outcome). |
| `az-post-exploitation/az-cloud-shell-post-exploitation.md#azure-cli-artifacts-in-persistent-storage` | Azure CLI artifacts in persistent storage | Microsoft.Storage/storageAccounts/listKeys/action | EXCLUDED | Strict principal-boundary audit: the catalog has no verified active principal or permission-gain path for this heading. |

## az-post-exploitation/az-container-apps-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-container-apps-post-exploitation.md` |  |  | STRUCTURAL | page reviewed: data exfiltration, tampering, evasion and DoS; identity-relevant sections mapped/excluded per heading |
| `az-post-exploitation/az-container-apps-post-exploitation.md#microsoftappmanagedenvironmentsstorageswrite-and-microsoftappcontainerappswrite` | `Microsoft.App/managedEnvironments/storages/write` and `Microsoft.App/containerApps/write` | Microsoft.App/containerApps/write,Microsoft.App/managedEnvironments/storages/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-container-apps-post-exploitation.md#microsoftappmanagedenvironmentswrite--suppress-or-redirect-environment-logs` | `Microsoft.App/managedEnvironments/write` — Suppress or redirect environment logs | Microsoft.App/managedEnvironments/*/write,Microsoft.App/managedEnvironments/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |

| `az-post-exploitation/az-container-apps-post-exploitation.md#microsoftappmanagedenvironmentsdaprcomponentswrite---redirect-a-future-dapr-operation` | `Microsoft.App/managedEnvironments/daprComponents/write` - Redirect a future Dapr operation | Microsoft.App/managedEnvironments/daprComponents/write | EXCLUDED | Redirects future data flows or discloses component secrets; no deterministic identity gain. |
## az-post-exploitation/az-container-registry-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-container-registry-post-exploitation.md` |  |  | STRUCTURAL | page reviewed: data exfiltration, tampering, evasion and DoS; identity-relevant sections mapped/excluded per heading |
| `az-post-exploitation/az-container-registry-post-exploitation.md#related-privesc-path-acr-tasks-managed-identities` | Related privesc path: ACR Tasks managed identities | Microsoft.ContainerRegistry/registries/runs/write,Microsoft.ContainerRegistry/registries/tasks/write | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-container-registry-privesc.md#microsoftcontainerregistryregistriestaskswrite`, `az-privilege-escalation/az-container-registry-privesc.md#microsoftcontainerregistryregistriestaskswrite` |
| `az-post-exploitation/az-container-registry-post-exploitation.md#microsoftcontainerregistryregistriespullread` | `Microsoft.ContainerRegistry/registries/pull/read` | Microsoft.ContainerRegistry/registries/pull/read | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-container-registry-post-exploitation.md#microsoftcontainerregistryregistriespushwrite` | `Microsoft.ContainerRegistry/registries/push/write` | Microsoft.ContainerRegistry/registries/push/write | EXCLUDED | Strict principal-boundary audit: The source permission or capability needed to perform the stated write/action is absent from requires; reviewed target evidence alone cannot establish the X permission to Y action escalation path. |
| `az-post-exploitation/az-container-registry-post-exploitation.md#microsoftcontainerregistryregistriespushwrite-microsoftcontainerinstancecontainergroupsrestartaction` | `Microsoft.ContainerRegistry/registries/push/write`, `Microsoft.ContainerInstance/containerGroups/restart/action` | Microsoft.ContainerInstance/containerGroups/restart/action,Microsoft.ContainerRegistry/registries/push/write | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-container-registry-privesc.md#microsoftcontainerregistryregistriespushwrite-microsoftcontainerinstancecontainergroupsrestartaction` |
| `az-post-exploitation/az-container-registry-post-exploitation.md#remove-registry-webhooks` | Remove registry webhooks |  | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |

## az-post-exploitation/az-cosmosDB-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-cosmosDB-post-exploitation.md` |  |  | STRUCTURAL | page reviewed: data exfiltration, tampering, evasion and DoS; identity-relevant sections are covered by existing entries or excluded below |
| `az-post-exploitation/az-cosmosDB-post-exploitation.md#az---cosmosdb-post-exploitation` | Az - CosmosDB Post Exploitation |  | STRUCTURAL | page title |
| `az-post-exploitation/az-cosmosDB-post-exploitation.md#cosmosdb` | CosmosDB |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-cosmosDB-post-exploitation.md#credential-access` | Credential access |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-cosmosDB-post-exploitation.md#data-plane-users--permissions--resource-tokens-scoped-credential-persistence` | Data-plane Users + Permissions → resource tokens (scoped-credential persistence) |  | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-cosmosDB-post-exploitation.md#data-export` | Data export |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-cosmosDB-post-exploitation.md#microsoftdocumentdblocationsrestorabledatabaseaccountsrestoreaction-restore-to-attacker-account-exfil` | `Microsoft.DocumentDB/locations/restorableDatabaseAccounts/restore/action` (restore-to-attacker-account exfil) | Microsoft.DocumentDB/databaseAccounts/write,Microsoft.DocumentDB/locations/restorableDatabaseAccounts/restore/action | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-cosmosDB-post-exploitation.md#microsoftdocumentdbdatabaseaccountsdatatransferjobswrite-server-side-copy-out` | `Microsoft.DocumentDB/databaseAccounts/dataTransferJobs/write` (server-side copy-out) | Microsoft.DocumentDB/databaseAccounts/dataTransferJobs/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-cosmosDB-post-exploitation.md#data-tampering` | Data tampering |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-cosmosDB-post-exploitation.md#microsoftdocumentdbdatabaseaccountsread--microsoftdocumentdbdatabaseaccountswrite` | `Microsoft.DocumentDB/databaseAccounts/read` && `Microsoft.DocumentDB/databaseAccounts/write` | Microsoft.DocumentDB/databaseAccounts/read,Microsoft.DocumentDB/databaseAccounts/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-cosmosDB-post-exploitation.md#microsoftdocumentdbdatabaseaccountssqldatabasescontainersread--microsoftdocumentdbdatabaseaccountssqldatabasescontainerswrite` | `Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/read` && `Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/write` | Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/read,Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-cosmosDB-post-exploitation.md#microsoftdocumentdbdatabaseaccountssqldatabaseswrite--microsoftdocumentdbdatabaseaccountssqldatabasesread` | `Microsoft.DocumentDB/databaseAccounts/sqlDatabases/write` && `Microsoft.DocumentDB/databaseAccounts/sqlDatabases/read` | Microsoft.DocumentDB/databaseAccounts/sqlDatabases/read,Microsoft.DocumentDB/databaseAccounts/sqlDatabases/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-cosmosDB-post-exploitation.md#microsoftdocumentdbdatabaseaccountssqldatabasescontainersuserdefinedfunctionswrite--microsoftdocumentdbdatabaseaccountssqldatabasescontainersuserdefinedfunctionsread` | `Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/userDefinedFunctions/write` && `Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/userDefinedFunctions/read` | Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/userDefinedFunctions/read,Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/userDefinedFunctions/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-cosmosDB-post-exploitation.md#microsoftdocumentdbdatabaseaccountssqldatabasescontainersstoredprocedureswrite--microsoftdocumentdbdatabaseaccountssqldatabasescontainersstoredproceduresread` | `Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/storedProcedures/write` && `Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/storedProcedures/read` | Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/storedProcedures/read,Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/storedProcedures/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-cosmosDB-post-exploitation.md#microsoftdocumentdbdatabaseaccountssqldatabasescontainerstriggerswrite--microsoftdocumentdbdatabaseaccountssqldatabasescontainerstriggersread` | `Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/triggers/write` && `Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/triggers/read` | Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/triggers/read,Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/triggers/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-cosmosDB-post-exploitation.md#microsoftdocumentdbdatabaseaccountsmongodbdatabasescollectionsread--microsoftdocumentdbdatabaseaccountsmongodbdatabasescollectionswrite` | `Microsoft.DocumentDB/databaseAccounts/mongodbDatabases/collections/read` && `Microsoft.DocumentDB/databaseAccounts/mongodbDatabases/collections/write` | Microsoft.DocumentDB/databaseAccounts/mongodbDatabases/collections/read,Microsoft.DocumentDB/databaseAccounts/mongodbDatabases/collections/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-cosmosDB-post-exploitation.md#microsoftdocumentdbdatabaseaccountsmongodbdatabaseswrite--microsoftdocumentdbdatabaseaccountsmongodbdatabasesread` | `Microsoft.DocumentDB/databaseAccounts/mongodbDatabases/write` && `Microsoft.DocumentDB/databaseAccounts/mongodbDatabases/read` | Microsoft.DocumentDB/databaseAccounts/mongodbDatabases/read,Microsoft.DocumentDB/databaseAccounts/mongodbDatabases/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-cosmosDB-post-exploitation.md#dosbreak` | DoS/Break |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-cosmosDB-post-exploitation.md#microsoftdocumentdbdatabaseaccountsfailoverprioritychangeaction` | `Microsoft.DocumentDB/databaseAccounts/failoverPriorityChange/action` | Microsoft.DocumentDB/databaseAccounts/failoverPriorityChange/action | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-cosmosDB-post-exploitation.md#microsoftdocumentdbdatabaseaccountsregeneratekeyaction` | `Microsoft.DocumentDB/databaseAccounts/regenerateKey/action` | Microsoft.DocumentDB/databaseAccounts/regenerateKey/action | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-cosmosDB-post-exploitation.md#cmk-revocation-denial-of-data--ransom` | CMK revocation "denial-of-data" / ransom | Microsoft.DocumentDB/databaseAccounts/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-cosmosDB-post-exploitation.md#throughputsettingswrite--migratetoautoscaleaction-denial-of-wallet` | `.../throughputSettings/write` + `migrateToAutoscale/action` (denial-of-wallet) |  | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-cosmosDB-post-exploitation.md#references` | References |  | STRUCTURAL | section grouping heading |

## az-post-exploitation/az-cost-management-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-cost-management-post-exploitation.md#cost-data-as-recon` | Cost data as recon |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-cost-management-post-exploitation.md#dismantling-spend-based-detection` | Dismantling spend-based detection |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-cost-management-post-exploitation.md#budgets--notifications-microsoftconsumptionbudgets` | Budgets + notifications (`Microsoft.Consumption/budgets`) | Microsoft.Consumption/budgets | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-cost-management-post-exploitation.md#cost-anomaly-alerts-microsoftcostmanagementscheduledactions-kind-insightalert` | Cost anomaly alerts (`Microsoft.CostManagement/scheduledActions`, kind `InsightAlert`) | Microsoft.CostManagement/scheduledActions | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-cost-management-post-exploitation.md#exports-microsoftcostmanagementexports` | Exports (`Microsoft.CostManagement/exports`) | Microsoft.CostManagement/exports | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-cost-management-post-exploitation.md#dosbreak` | DoS/Break |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-cost-management-post-exploitation.md` | Az - Cost Management Post Exploitation |  | EXCLUDED | page reviewed: post-exploitation techniques; rows below |

## az-post-exploitation/az-data-explorer-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-data-explorer-post-exploitation.md` |  |  | STRUCTURAL | page reviewed: data exfiltration, tampering, evasion and DoS; identity-relevant sections are covered by existing entries or excluded below |
| `az-post-exploitation/az-data-explorer-post-exploitation.md#az---data-explorer-post-exploitation` | Az - Data Explorer Post Exploitation |  | STRUCTURAL | page title |
| `az-post-exploitation/az-data-explorer-post-exploitation.md#azure-data-explorer` | Azure Data Explorer |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-data-explorer-post-exploitation.md#sandboxed-python--r-plugin--code-execution-on-the-cluster` | Sandboxed `python()` / `R` plugin — code execution on the cluster | Microsoft.Kusto/Clusters/AddLanguageExtensions/action | EXCLUDED | Sandboxed compute execution; page documents no managed-identity token access from the sandbox. |
| `az-post-exploitation/az-data-explorer-post-exploitation.md#data-export` | Data export |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-data-explorer-post-exploitation.md#continuous-export--external-tables-to-attacker-storage--bulk-exfiltration` | Continuous export / external tables to attacker storage — bulk exfiltration |  | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-data-explorer-post-exploitation.md#cross-cluster-follower-attach--near-real-time-exfil-to-an-attacker-cluster` | Cross-cluster follower attach — near-real-time exfil to an attacker cluster | Microsoft.Kusto/Clusters/AttachedDatabaseConfigurations/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-data-explorer-post-exploitation.md#data-tampering` | Data tampering |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-data-explorer-post-exploitation.md#data-connection-repoint--hijack--event-hub--iot-ingestion-tampering` | Data-connection repoint / hijack — Event Hub / IoT ingestion tampering | Microsoft.Kusto/Clusters/Databases/DataConnections/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-data-explorer-post-exploitation.md#security-control-bypass` | Security control bypass |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-data-explorer-post-exploitation.md#microsoftkustoclustersaddcalloutpoliciesaction--callout-policy--ssrf--exfil-egress` | `Microsoft.Kusto/Clusters/AddCalloutPolicies/action` — callout policy → SSRF / exfil egress | Microsoft.Kusto/Clusters/AddCalloutPolicies/action | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |

## az-post-exploitation/az-data-factory-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-data-factory-post-exploitation.md` |  |  | STRUCTURAL | page reviewed: data exfiltration, tampering, evasion and DoS; identity-relevant sections are covered by existing entries or excluded below |
| `az-post-exploitation/az-data-factory-post-exploitation.md#az---data-factory-post-exploitation` | Az - Data Factory Post Exploitation |  | STRUCTURAL | page title |
| `az-post-exploitation/az-data-factory-post-exploitation.md#data-factory` | Data Factory |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-data-factory-post-exploitation.md#data-export` | Data export |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-data-factory-post-exploitation.md#blind-sink-replacement-with-microsoftdatafactoryfactoriesdatasetswrite` | Blind sink replacement with `Microsoft.DataFactory/factories/datasets/write` | Microsoft.DataFactory/factories/datasets/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-data-factory-post-exploitation.md#blind-sink-replacement-with-microsoftdatafactoryfactorieslinkedserviceswrite` | Blind sink replacement with `Microsoft.DataFactory/factories/linkedservices/write` | Microsoft.DataFactory/factories/linkedservices/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-data-factory-post-exploitation.md#previewexfil-source-data-through-a-data-flow-debug-session` | Preview/exfil source data through a Data Flow debug session | Microsoft.DataFactory/factories/createdataflowdebugsession/action | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-data-factory-post-exploitation.md#read-plaintext-parameters-from-pipeline-run-history` | Read plaintext parameters from pipeline-run history | Microsoft.DataFactory/factories/pipelineruns/read,Microsoft.DataFactory/factories/querypipelineruns/action,Microsoft.DataFactory/factories/querypipelineruns/read | EXCLUDED | Data read. |

## az-post-exploitation/az-data-share-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-data-share-post-exploitation.md#in-place-data-explorer-cluster-level-tap-stealthiest` | In-place Data Explorer cluster-level tap (stealthiest) |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-data-share-post-exploitation.md#cross-tenant-snapshot-exfil-share-marquee` | Cross-tenant snapshot exfil share (marquee) |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-data-share-post-exploitation.md#scheduled-incremental-snapshot-persistence-headline` | Scheduled incremental-snapshot persistence (headline) |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-data-share-post-exploitation.md#dosbreak` | DoS/Break |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-data-share-post-exploitation.md` | Az - Data Share Post-Exploitation |  | EXCLUDED | page reviewed: post-exploitation techniques; rows below |

## az-post-exploitation/az-ddos-protection-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-ddos-protection-post-exploitation.md` |  |  | STRUCTURAL | page reviewed: data exfiltration, tampering, evasion and DoS; identity-relevant sections mapped/excluded per heading |
| `az-post-exploitation/az-ddos-protection-post-exploitation.md#silence-the-mitigation-telemetry` | Silence the mitigation telemetry | Microsoft.Insights/diagnosticSettings/delete,Microsoft.Insights/metricAlerts/delete | EXCLUDED | Security-control weakening, telemetry tampering or DoS; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-ddos-protection-post-exploitation.md#remove-protection-drop-mitigation--telemetry-in-one-write` | Remove protection (drop mitigation + telemetry in one write) | Microsoft.Network/publicIPAddresses/write,Microsoft.Network/virtualNetworks/write | EXCLUDED | Security-control weakening, telemetry tampering or DoS; no Azure/Entra principal is obtained. |

## az-post-exploitation/az-defender-easm-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-defender-easm-post-exploitation.md#loot-the-inventory-read-only-recon` | Loot the inventory (read-only recon) |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-defender-easm-post-exploitation.md#blind-discovery-so-new-exposure-is-never-indexed` | Blind discovery so new exposure is never indexed |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-defender-easm-post-exploitation.md#bury-an-asset-that-did-get-discovered` | Bury an asset that did get discovered |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-defender-easm-post-exploitation.md#dosbreak` | DoS/Break |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-defender-easm-post-exploitation.md` | Az - Defender EASM Post Exploitation |  | EXCLUDED | page reviewed: post-exploitation techniques; rows below |

## az-post-exploitation/az-defender-for-cloud-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-defender-for-cloud-post-exploitation.md#defender-for-resource-manager--arm_-arm-control-plane` | Defender for Resource Manager — `ARM_*` (ARM control plane) |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-defender-for-cloud-post-exploitation.md#defender-for-servers--vm_-scuba_-mde-host` | Defender for Servers — `VM_*`, `SCUBA_*`, MDE (host) |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-defender-for-cloud-post-exploitation.md#defender-for-storage--storage-blobfile-data-plane` | Defender for Storage — `Storage.*` (blob/file data plane) |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-defender-for-cloud-post-exploitation.md#defender-for-key-vault--kv_` | Defender for Key Vault — `KV_*` |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-defender-for-cloud-post-exploitation.md#defender-for-dns--azuredns_` | Defender for DNS — `AzureDNS_*` |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-defender-for-cloud-post-exploitation.md#defender-for-databases--sql-cosmos_` | Defender for Databases — `SQL.*`, `Cosmos_*` |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-defender-for-cloud-post-exploitation.md#defender-for-containers--k8s_-k8snode_` | Defender for Containers — `K8S_*`, `K8S.NODE_*` |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-defender-for-cloud-post-exploitation.md#defender-for-app-service--appservices_` | Defender for App Service — `AppServices_*` |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-defender-for-cloud-post-exploitation.md#defender-for-apis--ai--api_-aiazure_` | Defender for APIs / AI — `API_*`, `AI.Azure_*` |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-defender-for-cloud-post-exploitation.md#microsoftsecuritypricingswrite--downgrade-a-plan-to-free` | `Microsoft.Security/pricings/write` — downgrade a plan to Free | Microsoft.Security/pricings/write | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-defender-for-cloud-post-exploitation.md#microsoftsecurityalertssuppressionruleswrite--pre-dismiss-alerts` | `Microsoft.Security/alertsSuppressionRules/write` — pre-dismiss alerts | Microsoft.Security/alertsSuppressionRules/write | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-defender-for-cloud-post-exploitation.md#microsoftsecuritysecuritycontactswrite--silence-notifications` | `Microsoft.Security/securityContacts/write` — silence notifications | Microsoft.Security/securityContacts/write | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-defender-for-cloud-post-exploitation.md#microsoftsecurityalerts--dismissresolve-already-fired-alerts` | `Microsoft.Security/alerts` — dismiss/resolve already-fired alerts | Microsoft.Security/alerts | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-defender-for-cloud-post-exploitation.md#opting-resources-out-of-the-agents` | Opting resources out of the agents |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-defender-for-cloud-post-exploitation.md#microsoftsecurityautomationswritedelete--break-continuous-export` | `Microsoft.Security/automations/write\|delete` — break continuous export | Microsoft.Security/automations/write\|delete | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-defender-for-cloud-post-exploitation.md` | Az - Defender for Cloud Post Exploitation |  | EXCLUDED | page reviewed: post-exploitation techniques; rows below |

## az-post-exploitation/az-deployment-stacks-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-deployment-stacks-post-exploitation.md#actiononunmanage-deleteall-mass-destruction` | `actionOnUnmanage: deleteAll` mass destruction |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-deployment-stacks-post-exploitation.md` | Az - Deployment Stacks Post Exploitation |  | EXCLUDED | page reviewed: post-exploitation techniques; rows below |

## az-post-exploitation/az-elastic-san-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-elastic-san-post-exploitation.md#snapshot-export--re-mount-data-exfiltration` | Snapshot-export → re-mount data exfiltration |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-elastic-san-post-exploitation.md#dosbreak` | DoS/Break |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-elastic-san-post-exploitation.md` | Az - Elastic SAN Post Exploitation |  | EXCLUDED | page reviewed: post-exploitation techniques; rows below |

## az-post-exploitation/az-entra-id-logs-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-entra-id-logs-post-exploitation.md` | (page) |  | STRUCTURAL | page reviewed: post-exploitation: data/credential reads, telemetry tampering or DoS |
| `az-post-exploitation/az-entra-id-logs-post-exploitation.md#az---entra-id-logs-post-exploitation` | Az - Entra ID Logs Post Exploitation |  | STRUCTURAL | title/reference/intro heading |
| `az-post-exploitation/az-entra-id-logs-post-exploitation.md#entra-id-logs--monitoring` | Entra ID Logs & Monitoring |  | EXCLUDED | post-exploitation: data/credential reads, telemetry tampering or DoS |
| `az-post-exploitation/az-entra-id-logs-post-exploitation.md#telemetry-tampering` | Telemetry tampering |  | EXCLUDED | post-exploitation: data/credential reads, telemetry tampering or DoS |
| `az-post-exploitation/az-entra-id-logs-post-exploitation.md#operate-in-the-under-monitored-sign-in-sub-streams` | Operate in the under-monitored sign-in sub-streams |  | SUBSECTION | of #telemetry-tampering: EXCLUDED: post-exploitation: data/credential reads, telemetry tampering or DoS |
| `az-post-exploitation/az-entra-id-logs-post-exploitation.md#let-retention-do-the-deleting` | Let retention do the deleting |  | SUBSECTION | of #telemetry-tampering: EXCLUDED: post-exploitation: data/credential reads, telemetry tampering or DoS |
| `az-post-exploitation/az-entra-id-logs-post-exploitation.md#keep-grapharm-activity-dark` | Keep Graph/ARM activity dark |  | SUBSECTION | of #telemetry-tampering: EXCLUDED: post-exploitation: data/credential reads, telemetry tampering or DoS |
| `az-post-exploitation/az-entra-id-logs-post-exploitation.md#break-the-export-pipeline-the-stop-cloudtrail-analogue` | Break the export pipeline (the "stop CloudTrail" analogue) |  | SUBSECTION | of #telemetry-tampering: EXCLUDED: post-exploitation: data/credential reads, telemetry tampering or DoS |
| `az-post-exploitation/az-entra-id-logs-post-exploitation.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-post-exploitation/az-entra-id-protection-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-entra-id-protection-post-exploitation.md` | (page) |  | STRUCTURAL | page reviewed: post-exploitation: data/credential reads, telemetry tampering or DoS |
| `az-post-exploitation/az-entra-id-protection-post-exploitation.md#az---entra-id-protection-post-exploitation` | Az - Entra ID Protection Post Exploitation |  | STRUCTURAL | title/reference/intro heading |
| `az-post-exploitation/az-entra-id-protection-post-exploitation.md#entra-id-protection` | Entra ID Protection |  | EXCLUDED | post-exploitation: data/credential reads, telemetry tampering or DoS |
| `az-post-exploitation/az-entra-id-protection-post-exploitation.md#telemetry-tampering` | Telemetry tampering |  | EXCLUDED | post-exploitation: data/credential reads, telemetry tampering or DoS |
| `az-post-exploitation/az-entra-id-protection-post-exploitation.md#the-detections-and-how-each-is-triggered--avoided` | The detections, and how each is triggered / avoided |  | SUBSECTION | of #telemetry-tampering: EXCLUDED: post-exploitation: data/credential reads, telemetry tampering or DoS |
| `az-post-exploitation/az-entra-id-protection-post-exploitation.md#clearing-risk-if-you-have-the-rights` | Clearing risk (if you have the rights) |  | SUBSECTION | of #telemetry-tampering: EXCLUDED: post-exploitation: data/credential reads, telemetry tampering or DoS |
| `az-post-exploitation/az-entra-id-protection-post-exploitation.md#weaken-the-engine-tampering` | Weaken the engine (tampering) |  | SUBSECTION | of #telemetry-tampering: EXCLUDED: post-exploitation: data/credential reads, telemetry tampering or DoS |
| `az-post-exploitation/az-entra-id-protection-post-exploitation.md#dosbreak` | DoS/Break |  | EXCLUDED | post-exploitation: data/credential reads, telemetry tampering or DoS |
| `az-post-exploitation/az-entra-id-protection-post-exploitation.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-post-exploitation/az-event-hubs-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-event-hubs-post-exploitation.md#read-already-captured-avro-blobs-from-the-capture-storage-account` | Read already-captured Avro blobs from the capture storage account |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-event-hubs-post-exploitation.md#capture-repoint--archive-the-stream-to-attacker-storage-eventhubswrite` | Capture repoint — archive the stream to attacker storage (`eventhubs/write`) |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-event-hubs-post-exploitation.md#network-lock-out--exposure--networkrulesetswrite` | Network lock-out / exposure — `networkRuleSets/write` |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-event-hubs-post-exploitation.md#purge-retained-events-early--lower-messageretentionindays-eventhubswrite` | Purge retained events early — lower `messageRetentionInDays` (`eventhubs/write`) |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-event-hubs-post-exploitation.md#destructive-dos--delete-namespace--event-hub--consumer-group` | Destructive DoS — delete namespace / event hub / consumer group |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-event-hubs-post-exploitation.md#lock-out-sas-clients--disablelocalauthtrue-namespaceswrite` | Lock out SAS clients — `disableLocalAuth=true` (`namespaces/write`) |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-event-hubs-post-exploitation.md#geo-dr-failover--break-pairing-hijack-disasterrecoveryconfigs` | Geo-DR failover / break-pairing hijack (`disasterRecoveryConfigs/*`) |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-event-hubs-post-exploitation.md#customer-managed-key-cmk-revocation-dos` | Customer-managed key (CMK) revocation DoS |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-event-hubs-post-exploitation.md` | Az - Event Hubs Post Exploitation |  | EXCLUDED | page reviewed: post-exploitation techniques; rows below |
| `az-post-exploitation/az-event-hubs-post-exploitation.md#entra-event-data-access` | Entra event data access |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-event-hubs-post-exploitation.md#direct-entra-authenticated-event-read-and-injection` | Direct Entra-authenticated event read and injection |  | EXCLUDED | Strict principal-boundary audit: The declared target is a bounded authority rather than an identified target principal or an explicit grant of extra permissions to the caller. |

## az-post-exploitation/az-fabric-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-fabric-post-exploitation.md` |  |  | STRUCTURAL | page reviewed: data exfiltration, tampering, evasion and DoS; identity-relevant sections are covered by existing entries or excluded below |
| `az-post-exploitation/az-fabric-post-exploitation.md#az---fabric-post-exploitation` | Az - Fabric Post Exploitation |  | STRUCTURAL | page title |
| `az-post-exploitation/az-fabric-post-exploitation.md#microsoft-fabric` | Microsoft Fabric |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-fabric-post-exploitation.md#data-export` | Data export |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-fabric-post-exploitation.md#onelake-data-exfiltration-and-shortcut-abuse` | OneLake data exfiltration and shortcut abuse |  | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-fabric-post-exploitation.md#dosbreak` | DoS/Break |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-fabric-post-exploitation.md#capacity-arm-primitives--estate-wide-dos--cost-no-data-access` | Capacity ARM primitives — estate-wide DoS & cost (no data access) | Microsoft.Fabric/capacities/* | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-fabric-post-exploitation.md#references` | References |  | STRUCTURAL | section grouping heading |

## az-post-exploitation/az-file-share-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-file-share-post-exploitation.md#download-files-and-snapshots` | Download files and snapshots |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-file-share-post-exploitation.md#microsoftstoragestorageaccountsfileservicesfilesharesfilesread-microsoftstoragestorageaccountsfileservicesreadfilebackupsemanticsaction` | `Microsoft.Storage/storageAccounts/fileServices/fileshares/files/read`, `Microsoft.Storage/storageAccounts/fileServices/readFileBackupSemantics/action` | Microsoft.Storage/storageAccounts/fileServices/fileshares/files/read;Microsoft.Storage/storageAccounts/fileServices/readFileBackupSemantics/action | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-file-share-post-exploitation.md#microsoftstoragestorageaccountsfileservicesfilesharesfileswrite-microsoftstoragestorageaccountsfileserviceswritefilebackupsemanticsaction` | `Microsoft.Storage/storageAccounts/fileServices/fileshares/files/write`, `Microsoft.Storage/storageAccounts/fileServices/writeFileBackupSemantics/action` | Microsoft.Storage/storageAccounts/fileServices/fileshares/files/write;Microsoft.Storage/storageAccounts/fileServices/writeFileBackupSemantics/action | EXCLUDED | Strict principal-boundary audit: The source permission or capability needed to perform the stated write/action is absent from requires; reviewed target evidence alone cannot establish the X permission to Y action escalation path. |
| `az-post-exploitation/az-file-share-post-exploitation.md#microsoftstoragestorageaccountsfileservicesfilesharesfilesdelete-microsoftstoragestorageaccountsfileserviceswritefilebackupsemanticsaction` | `Microsoft.Storage/storageAccounts/fileServices/fileshares/files/delete`, `Microsoft.Storage/storageAccounts/fileServices/writeFileBackupSemantics/action` | Microsoft.Storage/storageAccounts/fileServices/fileshares/files/delete;Microsoft.Storage/storageAccounts/fileServices/writeFileBackupSemantics/action | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-file-share-post-exploitation.md` | Az - File Share Post Exploitation |  | EXCLUDED | page reviewed: post-exploitation techniques; rows below |

## az-post-exploitation/az-firewall-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-firewall-post-exploitation.md` |  |  | STRUCTURAL | page reviewed: data exfiltration, tampering, evasion and DoS; identity-relevant sections mapped/excluded per heading |
| `az-post-exploitation/az-firewall-post-exploitation.md#dns-proxy-caveat` | DNS proxy caveat | Microsoft.Network/*/write | EXCLUDED | Security-control weakening, telemetry tampering or DoS; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-firewall-post-exploitation.md#open-the-path-you-need-firewall-policy-edits` | Open the path you need (Firewall Policy edits) | Microsoft.Network/firewallPolicies/read,Microsoft.Network/firewallPolicies/ruleCollectionGroups/write | EXCLUDED | Security-control weakening, telemetry tampering or DoS; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-firewall-post-exploitation.md#disarm-threat-intel-and-idps-stop-the-alerts` | Disarm threat-intel and IDPS (stop the alerts) | Microsoft.Network/firewallPolicies/write | EXCLUDED | Security-control weakening, telemetry tampering or DoS; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-firewall-post-exploitation.md#cut-the-firewalls-logs` | Cut the firewall's logs | Microsoft.Insights/diagnosticSettings/delete,Microsoft.Insights/diagnosticSettings/write | EXCLUDED | Security-control weakening, telemetry tampering or DoS; no Azure/Entra principal is obtained. |

## az-post-exploitation/az-front-door-credential-skimming-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-front-door-credential-skimming-post-exploitation.md` |  |  | STRUCTURAL | page reviewed: data exfiltration, tampering, evasion and DoS; identity-relevant sections mapped/excluded per heading |
| `az-post-exploitation/az-front-door-credential-skimming-post-exploitation.md#credential-skimming-via-waf-custom-rules--log-analytics` | Credential Skimming via WAF Custom Rules + Log Analytics |  | EXCLUDED | Skims end-user credentials of a fronted app; content/user-dependent, not RBAC-derivable. |

## az-post-exploitation/az-function-apps-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-function-apps-post-exploitation.md` |  |  | STRUCTURAL | page reviewed: data exfiltration, tampering, evasion and DoS; identity-relevant sections mapped/excluded per heading |
| `az-post-exploitation/az-function-apps-post-exploitation.md#steal-managed-identity-tokens-via-identity_endpoint` | Steal managed-identity tokens via `$IDENTITY_ENDPOINT` |  | EXCLUDED | On-box outcome step; the reaching code-execution paths are the azure-functions-* / azure-appservice-* entries. |
| `az-post-exploitation/az-function-apps-post-exploitation.md#pivot-through-key-based-host-storage-settings` | Pivot through key-based host-storage settings | Microsoft.Web/sites/config/list/action | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-functions-app-privesc.md#microsoftwebsitesconfiglistaction`, `az-privilege-escalation/az-functions-app-privesc.md#storage-backed-deployment-content` |

## az-post-exploitation/az-guest-configuration-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-guest-configuration-post-exploitation.md` |  |  | STRUCTURAL | page reviewed: data exfiltration, tampering, evasion and DoS; identity-relevant sections mapped/excluded per heading |
| `az-post-exploitation/az-guest-configuration-post-exploitation.md#anti-forensics--delete-the-assignment-to-erase-on-box-artifacts` | Anti-forensics — delete the assignment to erase on-box artifacts | Microsoft.GuestConfiguration/guestConfigurationAssignments/delete | EXCLUDED | Security-control weakening, telemetry tampering or DoS; no Azure/Entra principal is obtained. |

## az-post-exploitation/az-hdinsight-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-hdinsight-post-exploitation.md` |  |  | STRUCTURAL | page reviewed: data exfiltration, tampering, evasion and DoS; identity-relevant sections are covered by existing entries or excluded below |
| `az-post-exploitation/az-hdinsight-post-exploitation.md#az---hdinsight-post-exploitation` | Az - HDInsight Post Exploitation |  | STRUCTURAL | page title |
| `az-post-exploitation/az-hdinsight-post-exploitation.md#hdinsight` | HDInsight |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-hdinsight-post-exploitation.md#telemetry-tampering` | Telemetry tampering |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-hdinsight-post-exploitation.md#disable-cluster-monitoring-defense-evasion` | Disable cluster monitoring (defense evasion) | Microsoft.HDInsight/clusters/extensions/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-hdinsight-post-exploitation.md#references` | References |  | STRUCTURAL | section grouping heading |

## az-post-exploitation/az-healthcare-apis-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-healthcare-apis-post-exploitation.md` |  |  | STRUCTURAL | page reviewed: data exfiltration, tampering, evasion and DoS; identity-relevant sections are covered by existing entries or excluded below |
| `az-post-exploitation/az-healthcare-apis-post-exploitation.md#az---healthcare-apis-fhir--dicom-post-exploitation` | Az - Healthcare APIs (FHIR / DICOM) Post-Exploitation |  | STRUCTURAL | page title |
| `az-post-exploitation/az-healthcare-apis-post-exploitation.md#azure-health-data-services` | Azure Health Data Services |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-healthcare-apis-post-exploitation.md#smart-on-fhir-idp-backdoor-persistence` | SMART-on-FHIR IdP backdoor (persistence) | Microsoft.HealthcareApis/workspaces/fhirservices/write | EXCLUDED | Persistence on FHIR data-plane authentication; data access only. |
| `az-post-exploitation/az-healthcare-apis-post-exploitation.md#self-grant-fhirdicom-data-roles-privesc` | Self-grant FHIR/DICOM data roles (privesc) | Microsoft.Authorization/roleAssignments/write | EXCLUDED | Moved to the healthcare privilege-escalation page; role-assignment outcome NEEDS SCHEMA for exact RBAC condition and newly effective service data role. |
| `az-post-exploitation/az-healthcare-apis-post-exploitation.md#data-export` | Data export |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-healthcare-apis-post-exploitation.md#dicom-bulk-imaging-exfil-to-attacker-storage-marquee` | DICOM bulk imaging exfil to attacker storage (marquee) |  | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-healthcare-apis-post-exploitation.md#fhir-export-full-phi-dump` | FHIR `$export` full PHI dump |  | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-healthcare-apis-post-exploitation.md#data-tampering` | Data tampering |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-healthcare-apis-post-exploitation.md#forge--overwrite-clinical-data-via-import-and-medtech-integrity` | Forge / overwrite clinical data via `$import` and MedTech (integrity) |  | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-healthcare-apis-post-exploitation.md#dosbreak` | DoS/Break |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-healthcare-apis-post-exploitation.md#references` | References |  | STRUCTURAL | section grouping heading |

## az-post-exploitation/az-intune-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-intune-post-exploitation.md` | (page) |  | STRUCTURAL | page reviewed: post-exploitation: data/credential reads, telemetry tampering or DoS |
| `az-post-exploitation/az-intune-post-exploitation.md#az---intune-post-exploitation` | Az - Intune Post Exploitation |  | STRUCTURAL | title/reference/intro heading |
| `az-post-exploitation/az-intune-post-exploitation.md#intune` | Intune |  | EXCLUDED | post-exploitation: data/credential reads, telemetry tampering or DoS |
| `az-post-exploitation/az-intune-post-exploitation.md#credential-access` | Credential access |  | EXCLUDED | post-exploitation: data/credential reads, telemetry tampering or DoS |
| `az-post-exploitation/az-intune-post-exploitation.md#credential-access--filevault--bitlocker-keys--laps-passwords` | Credential access — FileVault / BitLocker keys & LAPS passwords |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-intune-privesc.md#credential-access--filevault--bitlocker-keys--laps-passwords` |
| `az-post-exploitation/az-intune-post-exploitation.md#loot-secrets-from-existing-deployed-scripts-read-only` | Loot secrets from existing deployed scripts (read-only) |  | SUBSECTION | of #credential-access: EXCLUDED: post-exploitation: data/credential reads, telemetry tampering or DoS |
| `az-post-exploitation/az-intune-post-exploitation.md#dosbreak` | DoS/Break |  | EXCLUDED | post-exploitation: data/credential reads, telemetry tampering or DoS |
| `az-post-exploitation/az-intune-post-exploitation.md#fleet-destruction--dos-via-privileged-device-actions` | Fleet destruction / DoS via privileged device actions |  | SUBSECTION | of #dosbreak: EXCLUDED: post-exploitation: data/credential reads, telemetry tampering or DoS |
| `az-post-exploitation/az-intune-post-exploitation.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-post-exploitation/az-key-vault-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-key-vault-post-exploitation.md#microsoftkeyvaultvaultssecretsgetsecretaction` | Microsoft.KeyVault/vaults/secrets/getSecret/action | Microsoft.KeyVault/vaults/secrets/getSecret/action | EXCLUDED | Strict principal-boundary audit: The credential_stored_in_scope selector has no exact usable credential and identified target-principal evidence enforcement for this technique; a secret read or arbitrary configuration change alone is not an established principal escalation. |
| `az-post-exploitation/az-key-vault-post-exploitation.md#microsoftkeyvaultvaultssecretsrestoreaction` | Microsoft.KeyVault/vaults/secrets/restore/action | Microsoft.KeyVault/vaults/secrets/restore/action | EXCLUDED | Restores a previously stolen backup blob; needs prior secret access, no new principal beyond azure-keyvault-secret-read-sp-credentials. |
| `az-post-exploitation/az-key-vault-post-exploitation.md#microsoftkeyvaultvaultskeysunwrapkeyaction--recover-cmk-wrapped-data-encryption-keys` | `Microsoft.KeyVault/vaults/keys/unwrapKey/action` — recover CMK-wrapped data-encryption keys | Microsoft.KeyVault/vaults/keys/unwrapKey/action | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-key-vault-post-exploitation.md#export-an-exportable-certificatepfx-to-impersonate-a-service` | Export an exportable certificate/PFX to impersonate a service |  | EXCLUDED | Strict principal-boundary audit: The credential_stored_in_scope selector has no exact usable credential and identified target-principal evidence enforcement for this technique; a secret read or arbitrary configuration change alone is not an established principal escalation. |
| `az-post-exploitation/az-key-vault-post-exploitation.md#microsoftkeyvaultvaultskeysdecryptaction` | **Microsoft.KeyVault/vaults/keys/decrypt/action** | Microsoft.KeyVault/vaults/keys/decrypt/action** | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-key-vault-post-exploitation.md#microsoftkeyvaultvaultskeysrecoveraction` | Microsoft.KeyVault/vaults/keys/recover/action | Microsoft.KeyVault/vaults/keys/recover/action | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-key-vault-post-exploitation.md#microsoftkeyvaultvaultskeysencryptaction` | **Microsoft.KeyVault/vaults/keys/encrypt/action** | Microsoft.KeyVault/vaults/keys/encrypt/action** | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-key-vault-post-exploitation.md#microsoftkeyvaultvaultssecretssetsecretaction` | **Microsoft.KeyVault/vaults/secrets/setSecret/action** | Microsoft.KeyVault/vaults/secrets/setSecret/action** | EXCLUDED | Data tampering; the consumer-execution variant remains excluded pending exact object-to-consumer execution and identity-token proof (privesc page #write-only-secret-poisoning). |
| `az-post-exploitation/az-key-vault-post-exploitation.md#delete-the-vaults-diagnostic-settings-to-blind-the-auditevent-log` | Delete the vault's diagnostic settings to blind the `AuditEvent` log |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-key-vault-post-exploitation.md#microsoftkeyvaultvaultscertificatespurgeaction` | **Microsoft.KeyVault/vaults/certificates/purge/action** | Microsoft.KeyVault/vaults/certificates/purge/action** | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-key-vault-post-exploitation.md#microsoftkeyvaultvaultskeyspurgeaction` | **Microsoft.KeyVault/vaults/keys/purge/action** | Microsoft.KeyVault/vaults/keys/purge/action** | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-key-vault-post-exploitation.md#microsoftkeyvaultvaultssecretspurgeaction` | **Microsoft.KeyVault/vaults/secrets/purge/action** | Microsoft.KeyVault/vaults/secrets/purge/action** | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-key-vault-post-exploitation.md#microsoftkeyvaultvaultscertificatesdelete` | **Microsoft.KeyVault/vaults/certificates/delete** | Microsoft.KeyVault/vaults/certificates/delete** | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-key-vault-post-exploitation.md#microsoftkeyvaultvaultskeysdelete` | **Microsoft.KeyVault/vaults/keys/delete** | Microsoft.KeyVault/vaults/keys/delete** | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-key-vault-post-exploitation.md#microsoftkeyvaultvaultssecretsdelete` | **Microsoft.KeyVault/vaults/secrets/delete** | Microsoft.KeyVault/vaults/secrets/delete** | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-key-vault-post-exploitation.md#purge-the-whole-soft-deleted-vault-locationsdeletedvaultspurgeaction--mass-destruction--anti-forensics` | Purge the whole soft-deleted vault (`locations/deletedVaults/purge/action`) — mass destruction / anti-forensics |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-key-vault-post-exploitation.md` | Az - Key Vault Post Exploitation |  | EXCLUDED | page reviewed: post-exploitation techniques; rows below |

## az-post-exploitation/az-kubernetes-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-kubernetes-post-exploitation.md` |  |  | STRUCTURAL | page reviewed: data exfiltration, tampering, evasion and DoS; identity-relevant sections mapped/excluded per heading |
| `az-post-exploitation/az-kubernetes-post-exploitation.md#node--kubelet-managed-identity-theft-via-imds--cluster--azure-pivot` | Node / kubelet managed-identity theft via IMDS — cluster → Azure pivot |  | EXCLUDED | Cluster -> Azure pivot is modelled by k8s/cloud_pivot.yaml k8s-cloud-node-cloud-identity from cluster-admin. |
| `az-post-exploitation/az-kubernetes-post-exploitation.md#managed-namespace-credential-retrieval` | Managed namespace credential retrieval | Microsoft.ContainerService/managedClusters/managedNamespaces/listCredential/action | EXCLUDED | Strict principal-boundary audit: The declared target is a bounded authority rather than an identified target principal or an explicit grant of extra permissions to the caller. |
| `az-post-exploitation/az-kubernetes-post-exploitation.md#add-an-attacker-influenced-node-pool-agentpoolswrite` | Add an attacker-influenced node pool (`agentPools/write`) | Microsoft.ContainerService/managedClusters/agentPools/write,Microsoft.HybridContainerService/provisionedClusters/agentPools/write | EXCLUDED | New node pool inherits the cluster kubelet identity; reaching it needs in-cluster code execution modelled by k8s entries. |
| `az-post-exploitation/az-kubernetes-post-exploitation.md#api-server-network-exposure-managedclusterswrite--apiserveraccessprofile` | API-server network exposure (`managedClusters/write` — `apiServerAccessProfile`) | Microsoft.ContainerService/managedClusters/write | EXCLUDED | Network/traffic interception, exposure or DNS tampering; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-kubernetes-post-exploitation.md#cluster-certificate-rotation--invalidate-all-kubeconfigs-rotateclustercertificatesaction` | Cluster-certificate rotation — invalidate all kubeconfigs (`rotateClusterCertificates/action`) | Microsoft.ContainerService/managedClusters/rotateClusterCertificates/action | EXCLUDED | Security-control weakening, telemetry tampering or DoS; no Azure/Entra principal is obtained. |

## az-post-exploitation/az-log-analytics-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-log-analytics-post-exploitation.md#reading-the-workspace--loot--rule-recon` | Reading the workspace = loot + rule recon |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-log-analytics-post-exploitation.md#microsoftoperationalinsightsworkspacesdataexportswrite--continuous-log-exfiltration` | `Microsoft.OperationalInsights/workspaces/dataExports/write` — continuous log exfiltration | Microsoft.OperationalInsights/workspaces/dataExports/write | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-log-analytics-post-exploitation.md#workspacessearchjobswrite--restorelogswrite--read-basicarchive-tier--archived-data` | `workspaces/searchJobs/write` + `restoreLogs/write` — read Basic/Archive-tier & archived data |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-log-analytics-post-exploitation.md#workspace-shared-keys-and-log-injection` | Workspace shared keys and log injection |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-log-analytics-post-exploitation.md#log-forgery-via-the-modern-logs-ingestion-api-datacollectionrulesdatawrite-no-shared-key` | Log forgery via the modern Logs Ingestion API (`dataCollectionRules/data/write`, no shared key) |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-log-analytics-post-exploitation.md#microsoftoperationalinsightsworkspacessavedsearcheswrite--poison-the-kql-functions--computer-groups-behind-detections` | `Microsoft.OperationalInsights/workspaces/savedSearches/write` — poison the KQL functions / computer groups behind detections | Microsoft.OperationalInsights/workspaces/savedSearches/write | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-log-analytics-post-exploitation.md#downgrade-a-tables-plan-silently-kills-log-alerts` | Downgrade a table's plan (silently kills log alerts) |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-log-analytics-post-exploitation.md#shrink-retention--archive` | Shrink retention / archive |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-log-analytics-post-exploitation.md#purge-specific-rows-the-loud-thorough-one` | Purge specific rows (the loud, thorough one) |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-log-analytics-post-exploitation.md#cut-ingestion-upstream-cleaner-than-purge` | Cut ingestion upstream (cleaner than purge) |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-log-analytics-post-exploitation.md#workspaceslinkedstorageaccountswrite--repoint-byos-storage` | `workspaces/linkedStorageAccounts/write` — repoint BYOS storage |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-log-analytics-post-exploitation.md` | Az - Log Analytics Post Exploitation |  | EXCLUDED | page reviewed: post-exploitation techniques; rows below |

## az-post-exploitation/az-logic-apps-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-logic-apps-post-exploitation.md` |  |  | STRUCTURAL | page reviewed: data exfiltration, tampering, evasion and DoS; identity-relevant sections mapped/excluded per heading |
| `az-post-exploitation/az-logic-apps-post-exploitation.md#microsoftlogicworkflowsread-microsoftlogicworkflowswrite--microsoftmanagedidentityuserassignedidentitiesassignaction` | `Microsoft.Logic/workflows/read`, `Microsoft.Logic/workflows/write` && `Microsoft.ManagedIdentity/userAssignedIdentities/assign/action` | Microsoft.Logic/workflows/read,Microsoft.Logic/workflows/write,Microsoft.ManagedIdentity/userAssignedIdentities/assign/action | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-logic-apps-privesc.md#microsoftresourcessubscriptionsresourcegroupsread-microsoftlogicworkflowsread-microsoftlogicworkflowswrite--microsoftmanagedidentityuserassignedidentitiesassignaction--microsoftlogicworkflowstriggersrunaction` |
| `az-post-exploitation/az-logic-apps-post-exploitation.md#microsoftlogicworkflowslistswaggeraction---workflow-openapi--endpoint-disclosure` | `Microsoft.Logic/workflows/listSwagger/action` - Workflow OpenAPI / endpoint disclosure | Microsoft.Logic/workflows/listSwagger/action | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-logic-apps-post-exploitation.md#microsoftresourcessubscriptionsresourcegroupsread--microsoftlogicintegrationaccountspartnerswrite` | `Microsoft.Resources/subscriptions/resourcegroups/read` && `Microsoft.Logic/integrationAccounts/partners/write` | Microsoft.Logic/integrationAccounts/partners/write,Microsoft.Resources/subscriptions/resourcegroups/read | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-logic-apps-post-exploitation.md#microsoftwebsitesconfiglistaction-microsoftwebsitesread--microsoftwebsitesconfigwrite` | `Microsoft.Web/sites/config/list/action`, `Microsoft.Web/sites/read` && `Microsoft.Web/sites/config/write` | Microsoft.Web/sites/config/list/action,Microsoft.Web/sites/config/write,Microsoft.Web/sites/read | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-app-services-privesc.md#microsoftwebsitesconfigwrite` |
| `az-post-exploitation/az-logic-apps-post-exploitation.md#microsoftlogicintegrationaccountswrite` | `Microsoft.Logic/integrationAccounts/write` | Microsoft.Logic/integrationAccounts/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-logic-apps-post-exploitation.md#microsoftresourcessubscriptionsresourcegroupsread--microsoftlogicintegrationaccountsbatchconfigurationswrite` | `Microsoft.Resources/subscriptions/resourcegroups/read` && `Microsoft.Logic/integrationAccounts/batchConfigurations/write` | Microsoft.Logic/integrationAccounts/batchConfigurations/write,Microsoft.Resources/subscriptions/resourcegroups/read | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-logic-apps-post-exploitation.md#microsoftresourcessubscriptionsresourcegroupsread--microsoftlogicintegrationaccountsmapswrite` | `Microsoft.Resources/subscriptions/resourcegroups/read` && `Microsoft.Logic/integrationAccounts/maps/write` | Microsoft.Logic/integrationAccounts/maps/write,Microsoft.Resources/subscriptions/resourcegroups/read | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-logic-apps-post-exploitation.md#microsoftresourcessubscriptionsresourcegroupsread--microsoftlogicintegrationaccountssessionswrite` | `Microsoft.Resources/subscriptions/resourcegroups/read` && `Microsoft.Logic/integrationAccounts/sessions/write` | Microsoft.Logic/integrationAccounts/sessions/write,Microsoft.Resources/subscriptions/resourcegroups/read | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-logic-apps-post-exploitation.md#microsoftwebsitesread-microsoftwebsiteswrite` | `Microsoft.Web/sites/read`, `Microsoft.Web/sites/write` | Microsoft.Web/sites/read,Microsoft.Web/sites/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-logic-apps-post-exploitation.md#microsoftwebsitesstopaction-microsoftwebsitesstartaction--microsoftwebsitesrestartaction` | `Microsoft.Web/sites/stop/action`, `Microsoft.Web/sites/start/action` \|\| `Microsoft.Web/sites/restart/action` | Microsoft.Web/sites/restart/action,Microsoft.Web/sites/start/action,Microsoft.Web/sites/stop/action | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-logic-apps-post-exploitation.md#delete` | "*/delete" |  | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-logic-apps-post-exploitation.md#microsoftlogicworkflowsregenerateaccesskeyaction` | `Microsoft.Logic/workflows/regenerateAccessKey/action` | Microsoft.Logic/workflows/regenerateAccessKey/action | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |

## az-post-exploitation/az-maintenance-and-update-manager-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-maintenance-and-update-manager-post-exploitation.md` |  |  | STRUCTURAL | page reviewed: data exfiltration, tampering, evasion and DoS; identity-relevant sections mapped/excluded per heading |
| `az-post-exploitation/az-maintenance-and-update-manager-post-exploitation.md#anti-patching-persistence-keep-the-foothold-exploitable` | Anti-patching persistence (keep the foothold exploitable) | Microsoft.Maintenance/configurationAssignments/delete,Microsoft.Maintenance/maintenanceConfigurations/write | EXCLUDED | Security-control weakening, telemetry tampering or DoS; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-maintenance-and-update-manager-post-exploitation.md#forced-maintenance-apply--reboot-availability` | Forced maintenance apply / reboot (availability) | Microsoft.Maintenance/*,Microsoft.Maintenance/applyUpdates/write | EXCLUDED | Security-control weakening, telemetry tampering or DoS; no Azure/Entra principal is obtained. |

## az-post-exploitation/az-migrate-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-migrate-post-exploitation.md` |  |  | STRUCTURAL | page reviewed: data exfiltration, tampering, evasion and DoS; identity-relevant sections mapped/excluded per heading |
| `az-post-exploitation/az-migrate-post-exploitation.md#overpowered-migrate-execution-roles--storage--compute-takeover-privilege-source` | Overpowered Migrate execution roles → storage & compute takeover (privilege source) |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputevirtualmachineswrite-os-disk-swap` |
| `az-post-exploitation/az-migrate-post-exploitation.md#appliance-host--credential-jackpot-enrichment` | Appliance host = credential jackpot (enrichment) |  | EXCLUDED | Requires host compromise of the appliance; yields on-prem credentials, not an Azure/Entra principal. |
| `az-post-exploitation/az-migrate-post-exploitation.md#on-prem-estate-recon-via-read-only-rbac-marquee` | On-prem estate recon via read-only RBAC (marquee) | Microsoft.Migrate/*/read,Microsoft.OffAzure/*/read | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |

## az-post-exploitation/az-monitor-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-monitor-post-exploitation.md#abusing-alert-automation-turning-a-defence-into-an-execution-surface` | Abusing alert automation (turning a defence into an execution surface) |  | EXCLUDED | Strict principal-boundary audit: The source permission or capability needed to perform the stated write/action is absent from requires; reviewed target evidence alone cannot establish the X permission to Y action escalation path. |
| `az-post-exploitation/az-monitor-post-exploitation.md#the-free-lane-reads` | The free lane: reads |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-monitor-post-exploitation.md#microsoftinsightsdatacollectionruleswrite--associations--turn-azure-monitor-agent-into-a-file-exfiltrator` | `Microsoft.Insights/dataCollectionRules/write` (+ associations) — turn Azure Monitor Agent into a file exfiltrator | Microsoft.Insights/dataCollectionRules/write | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-monitor-post-exploitation.md#microsoftinsightsactiongroupswrite--plant-attacker-receivers-alert-data-exfil--execution-wiring` | `Microsoft.Insights/actionGroups/write` — plant attacker receivers (alert-data exfil + execution wiring) | Microsoft.Insights/actionGroups/write | EXCLUDED | Wires alerts to attacker-owned receivers: alert-data exfiltration and execution of automation the attacker already controls. |
| `az-post-exploitation/az-monitor-post-exploitation.md#cutting-telemetry-what-reaches-the-siem` | Cutting telemetry (what reaches the SIEM) |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-monitor-post-exploitation.md#microsoftinsightsdatacollectionrulesdatawrite--forge-logs-via-the-modern-logs-ingestion-api` | `Microsoft.Insights/dataCollectionRules/data/write` — forge logs via the modern Logs Ingestion API | Microsoft.Insights/dataCollectionRules/data/write | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-monitor-post-exploitation.md#delete--narrow-a-diagnostic-setting` | Delete / narrow a diagnostic setting |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-monitor-post-exploitation.md#delete-a-data-collection-rule-association-surgical-host-blind-spot` | Delete a Data Collection Rule Association (surgical host blind spot) |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-monitor-post-exploitation.md#disable-alert-rules` | Disable alert rules |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-monitor-post-exploitation.md` | Az - Azure Monitor Post Exploitation |  | EXCLUDED | page reviewed: post-exploitation techniques; rows below |

## az-post-exploitation/az-mysql-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-mysql-post-exploitation.md` |  |  | STRUCTURAL | page reviewed: data exfiltration, tampering, evasion and DoS; identity-relevant sections are covered by existing entries or excluded below |
| `az-post-exploitation/az-mysql-post-exploitation.md#az---mysql-post-exploitation` | Az - MySQL Post Exploitation |  | STRUCTURAL | page title |
| `az-post-exploitation/az-mysql-post-exploitation.md#mysql-databases` | MySQL Databases |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-mysql-post-exploitation.md#microsoftdbformysqlflexibleserversdatabaseswrite--microsoftdbformysqlflexibleserversdatabasesread` | `Microsoft.DBforMySQL/flexibleServers/databases/write` && `Microsoft.DBforMySQL/flexibleServers/databases/read` | Microsoft.DBforMySQL/flexibleServers/databases/read,Microsoft.DBforMySQL/flexibleServers/databases/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-mysql-post-exploitation.md#microsoftdbformysqlflexibleserversread-microsoftdbformysqlflexibleserverswrite--microsoftmanagedidentityuserassignedidentitiesassignaction` | `Microsoft.DBforMySQL/flexibleServers/read`, `Microsoft.DBforMySQL/flexibleServers/write` && `Microsoft.ManagedIdentity/userAssignedIdentities/assign/action` | Microsoft.DBforMySQL/flexibleServers/read,Microsoft.DBforMySQL/flexibleServers/write,Microsoft.ManagedIdentity/userAssignedIdentities/assign/action | EXCLUDED | UAMI attach is the Entra-auth prerequisite (see azure-mysql-flexible-entra-admin-write); no code path runs as the identity. |
| `az-post-exploitation/az-mysql-post-exploitation.md#microsoftdbformysqlflexibleserversstartaction` | `Microsoft.DBforMySQL/flexibleServers/start/action` | Microsoft.DBforMySQL/flexibleServers/start/action | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-mysql-post-exploitation.md#data-export` | Data export |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-mysql-post-exploitation.md#full-server-exfiltration-with-flexibleserversbackupandexportaction` | Full-server exfiltration with `flexibleServers/backupAndExport/action` | Microsoft.DBforMySQL/flexibleServers/backupAndExport/action | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-mysql-post-exploitation.md#data-tampering` | Data tampering |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-mysql-post-exploitation.md#microsoftdbformysqlflexibleserversresetgtidaction` | `Microsoft.DBforMySQL/flexibleServers/resetGtid/action` | Microsoft.DBforMySQL/flexibleServers/resetGtid/action | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-mysql-post-exploitation.md#security-control-bypass` | Security control bypass |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-mysql-post-exploitation.md#microsoftdbformysqlflexibleserversfirewallruleswrite` | `Microsoft.DBforMySQL/flexibleServers/firewallRules/write` | Microsoft.DBforMySQL/flexibleServers/firewallRules/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-mysql-post-exploitation.md#firewall-bypassing-reachability-with-flexibleserversprivateendpointconnectionsapprovalaction` | Firewall-bypassing reachability with `flexibleServers/privateEndpointConnectionsApproval/action` | Microsoft.DBforMySQL/flexibleServers/privateEndpointConnectionsApproval/action | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-mysql-post-exploitation.md#deploy-and-run-a-sql-workflow-from-github-actions` | Deploy and run a SQL workflow from GitHub Actions |  | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-mysql-post-exploitation.md#telemetry-tampering` | Telemetry tampering |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-mysql-post-exploitation.md#microsoftdbformysqlflexibleserversadvancedthreatprotectionsettingswrite` | `Microsoft.DBforMySQL/flexibleServers/advancedThreatProtectionSettings/write` | Microsoft.DBforMySQL/flexibleServers/advancedThreatProtectionSettings/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-mysql-post-exploitation.md#sever-the-audit-export-pipeline-with-diagnosticsettingswritedelete` | Sever the audit-export pipeline with `diagnosticSettings/write`/`delete` | Microsoft.DBforMySQL/flexibleServers/providers/Microsoft.Insights/diagnosticSettings/write,Microsoft.Insights/diagnosticSettings/* | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-mysql-post-exploitation.md#microsoftdbformysqlflexibleserversupdateconfigurationsaction` | `Microsoft.DBforMySQL/flexibleServers/updateConfigurations/action` | Microsoft.DBforMySQL/flexibleServers/updateConfigurations/action | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-mysql-post-exploitation.md#dosbreak` | DoS/Break |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-mysql-post-exploitation.md#microsoftdbformysqlflexibleserversstopaction` | `Microsoft.DBforMySQL/flexibleServers/stop/action` | Microsoft.DBforMySQL/flexibleServers/stop/action | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-mysql-post-exploitation.md#delete` | `*/delete` |  | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-mysql-post-exploitation.md#references` | References |  | STRUCTURAL | section grouping heading |

## az-post-exploitation/az-netapp-files-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-netapp-files-post-exploitation.md#export-policy-hijack--mount-and-readwrite-all-data-marquee` | Export-policy hijack → mount and read/write all data (marquee) |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-netapp-files-post-exploitation.md#snapshot-restore-to-new-volume-defeat-source-lockdown` | Snapshot restore-to-new-volume (defeat source lockdown) |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-netapp-files-post-exploitation.md#replication-out-for-continuous-exfil-persistence` | Replication-out for continuous exfil (persistence) |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-netapp-files-post-exploitation.md#destruction--ransom-cluster-data-loss--availability` | Destruction / ransom cluster (data loss & availability) |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-netapp-files-post-exploitation.md` | Az - NetApp Files Post-Exploitation |  | EXCLUDED | page reviewed: post-exploitation techniques; rows below |

## az-post-exploitation/az-pim-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-pim-post-exploitation.md` | (page) |  | STRUCTURAL | page reviewed: post-exploitation: data/credential reads, telemetry tampering or DoS |
| `az-post-exploitation/az-pim-post-exploitation.md#az---pim-post-exploitation` | Az - PIM Post Exploitation |  | STRUCTURAL | title/reference/intro heading |
| `az-post-exploitation/az-pim-post-exploitation.md#privileged-identity-management-pim` | Privileged Identity Management (PIM) |  | EXCLUDED | post-exploitation: data/credential reads, telemetry tampering or DoS |
| `az-post-exploitation/az-pim-post-exploitation.md#prefer-eligibility-over-active-standing-privilege` | Prefer eligibility over active standing privilege |  | SUBSECTION | of #privileged-identity-management-pim: EXCLUDED: post-exploitation: data/credential reads, telemetry tampering or DoS |
| `az-post-exploitation/az-pim-post-exploitation.md#data-export` | Data export |  | EXCLUDED | post-exploitation: data/credential reads, telemetry tampering or DoS |
| `az-post-exploitation/az-pim-post-exploitation.md#reconnaissance-value` | Reconnaissance value |  | SUBSECTION | of #data-export: EXCLUDED: post-exploitation: data/credential reads, telemetry tampering or DoS |
| `az-post-exploitation/az-pim-post-exploitation.md#telemetry-tampering` | Telemetry tampering |  | EXCLUDED | post-exploitation: data/credential reads, telemetry tampering or DoS |
| `az-post-exploitation/az-pim-post-exploitation.md#what-pim-emits-when-you-activate--and-how-to-blunt-each` | What PIM emits when you activate — and how to blunt each |  | SUBSECTION | of #telemetry-tampering: EXCLUDED: post-exploitation: data/credential reads, telemetry tampering or DoS |
| `az-post-exploitation/az-pim-post-exploitation.md#dont-trip-the-identity-side-detections` | Don't trip the identity-side detections |  | SUBSECTION | of #telemetry-tampering: EXCLUDED: post-exploitation: data/credential reads, telemetry tampering or DoS |
| `az-post-exploitation/az-pim-post-exploitation.md#dosbreak` | DoS/Break |  | EXCLUDED | post-exploitation: data/credential reads, telemetry tampering or DoS |
| `az-post-exploitation/az-pim-post-exploitation.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-post-exploitation/az-playwright-workspaces-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-playwright-workspaces-post-exploitation.md` |  |  | STRUCTURAL | page reviewed: data exfiltration, tampering, evasion and DoS; identity-relevant sections mapped/excluded per heading |
| `az-post-exploitation/az-playwright-workspaces-post-exploitation.md#workspace-access-token-creation` | Workspace access-token creation |  | EXCLUDED | NEEDS SCHEMA: a Playwright workspace token may confer bounded workspace authority, but the exact token subject, scope, usable token, new operation, and prior-absence proof are not verified. |

## az-post-exploitation/az-policy-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-policy-post-exploitation.md#1-enforcementmode--donotenforce` | 1. `enforcementMode = DoNotEnforce` |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-policy-post-exploitation.md#2-notscopes--carve-your-target-out` | 2. `notScopes` — carve your target out |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-policy-post-exploitation.md#3-policy-exemption` | 3. Policy exemption |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-policy-post-exploitation.md#4-overrides--parameters` | 4. Overrides / parameters |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-policy-post-exploitation.md#5-assignment-deletion-loudest` | 5. Assignment deletion (loudest) |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-policy-post-exploitation.md#neutralising-auditdetection-policies` | Neutralising audit/detection policies |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-policy-post-exploitation.md#dosbreak` | DoS/Break |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-policy-post-exploitation.md` | Az - Azure Policy Post Exploitation |  | EXCLUDED | page reviewed: post-exploitation techniques; rows below |

## az-post-exploitation/az-postgresql-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-postgresql-post-exploitation.md` |  |  | STRUCTURAL | page reviewed: data exfiltration, tampering, evasion and DoS; identity-relevant sections are covered by existing entries or excluded below |
| `az-post-exploitation/az-postgresql-post-exploitation.md#az---postgresql-post-exploitation` | Az - PostgreSQL Post Exploitation |  | STRUCTURAL | page title |
| `az-post-exploitation/az-postgresql-post-exploitation.md#postgresql-databases` | PostgreSQL Databases |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-postgresql-post-exploitation.md#microsoftdbforpostgresqlflexibleserversdatabaseswrite--microsoftdbforpostgresqlflexibleserversdatabasesread` | `Microsoft.DBforPostgreSQL/flexibleServers/databases/write` && `Microsoft.DBforPostgreSQL/flexibleServers/databases/read` | Microsoft.DBforPostgreSQL/flexibleServers/databases/read,Microsoft.DBforPostgreSQL/flexibleServers/databases/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-postgresql-post-exploitation.md#microsoftdbforpostgresqlflexibleserversstartaction` | `Microsoft.DBforPostgreSQL/flexibleServers/start/action` | Microsoft.DBforPostgreSQL/flexibleServers/start/action | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-postgresql-post-exploitation.md#microsoftdbforpostgresqlflexibleserversread-microsoftdbforpostgresqlflexibleserverswrite--microsoftmanagedidentityuserassignedidentitiesassignaction` | `Microsoft.DBforPostgreSQL/flexibleServers/read`, `Microsoft.DBforPostgreSQL/flexibleServers/write` && `Microsoft.ManagedIdentity/userAssignedIdentities/assign/action` | Microsoft.DBforPostgreSQL/flexibleServers/read,Microsoft.DBforPostgreSQL/flexibleServers/write,Microsoft.ManagedIdentity/userAssignedIdentities/assign/action | EXCLUDED | UAMI attach for Entra auth/CMK (see azure-postgresql-flexible-entra-admin-write); no code path runs as the identity. |
| `az-post-exploitation/az-postgresql-post-exploitation.md#data-export` | Data export |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-postgresql-post-exploitation.md#use-azure_storage-extension-to-access-storage-accounts` | Use `azure_storage` extension to access Storage accounts | Microsoft.DBforPostgreSQL/flexibleServers/configurations/write | EXCLUDED | Partial identity use: server system MI only reachable for blob reads via azure_storage; no token or arbitrary call as the MI. |
| `az-post-exploitation/az-postgresql-post-exploitation.md#full-server-exfiltration-with-flexibleserversltrbackupaction` | Full-server exfiltration with `flexibleServers/ltrBackup/action` | Microsoft.DBforPostgreSQL/flexibleServers/ltrBackup/action | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-postgresql-post-exploitation.md#security-control-bypass` | Security control bypass |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-postgresql-post-exploitation.md#microsoftdbforpostgresqlflexibleserversfirewallruleswrite-microsoftdbforpostgresqlflexibleserversread--microsoftdbforpostgresqlflexibleserversfirewallrulesread` | `Microsoft.DBforPostgreSQL/flexibleServers/firewallRules/write`, `Microsoft.DBforPostgreSQL/flexibleServers/read` && `Microsoft.DBforPostgreSQL/flexibleServers/firewallRules/read` | Microsoft.DBforPostgreSQL/flexibleServers/firewallRules/read,Microsoft.DBforPostgreSQL/flexibleServers/firewallRules/write,Microsoft.DBforPostgreSQL/flexibleServers/read | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-postgresql-post-exploitation.md#firewall-bypassing-reachability-with-flexibleserversprivateendpointconnectionsapprovalaction` | Firewall-bypassing reachability with `flexibleServers/privateEndpointConnectionsApproval/action` | Microsoft.DBforPostgreSQL/flexibleServers/privateEndpointConnectionsApproval/action | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-postgresql-post-exploitation.md#telemetry-tampering` | Telemetry tampering |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-postgresql-post-exploitation.md#microsoftdbforpostgresqlflexibleserversconfigurationswrite--microsoftdbforpostgresqlflexibleserversconfigurationsread` | `Microsoft.DBforPostgreSQL/flexibleServers/configurations/write` && `Microsoft.DBforPostgreSQL/flexibleServers/configurations/read` | Microsoft.DBforPostgreSQL/flexibleServers/configurations/read,Microsoft.DBforPostgreSQL/flexibleServers/configurations/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-postgresql-post-exploitation.md#microsoftdbforpostgresqlflexibleserversadvancedthreatprotectionsettingswrite--microsoftdbforpostgresqlflexibleserversadvancedthreatprotectionsettingsread` | `Microsoft.DBforPostgreSQL/flexibleServers/advancedThreatProtectionSettings/write` && `Microsoft.DBforPostgreSQL/flexibleServers/advancedThreatProtectionSettings/read` | Microsoft.DBforPostgreSQL/flexibleServers/advancedThreatProtectionSettings/read,Microsoft.DBforPostgreSQL/flexibleServers/advancedThreatProtectionSettings/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-postgresql-post-exploitation.md#sever-the-audit-export-pipeline-with-diagnosticsettingswritedelete` | Sever the audit-export pipeline with `diagnosticSettings/write`/`delete` | Microsoft.DBforPostgreSQL/flexibleServers/providers/Microsoft.Insights/diagnosticSettings/write,Microsoft.Insights/diagnosticSettings/* | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-postgresql-post-exploitation.md#dosbreak` | DoS/Break |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-postgresql-post-exploitation.md#microsoftdbforpostgresqlflexibleserversstopaction` | `Microsoft.DBforPostgreSQL/flexibleServers/stop/action` | Microsoft.DBforPostgreSQL/flexibleServers/stop/action | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-postgresql-post-exploitation.md#delete` | `*/delete` |  | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-postgresql-post-exploitation.md#references` | References |  | STRUCTURAL | section grouping heading |

## az-post-exploitation/az-purview-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-purview-post-exploitation.md` |  |  | STRUCTURAL | page reviewed: data exfiltration, tampering, evasion and DoS; identity-relevant sections are covered by existing entries or excluded below |
| `az-post-exploitation/az-purview-post-exploitation.md#az---purview-post-exploitation` | Az - Purview Post Exploitation |  | STRUCTURAL | page title |
| `az-post-exploitation/az-purview-post-exploitation.md#purview` | Purview |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-purview-post-exploitation.md#abuse-the-scanning-identity` | Abuse the scanning identity |  | EXCLUDED | Scanner MI use is limited to scans of registered sources; not RBAC-derivable token access (see az-purview-privesc entries). |
| `az-post-exploitation/az-purview-post-exploitation.md#data-export` | Data export |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-purview-post-exploitation.md#the-data-map-as-a-targeting-oracle` | The Data Map as a targeting oracle |  | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-purview-post-exploitation.md#telemetry-tampering` | Telemetry tampering |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-purview-post-exploitation.md#tampering-blind-the-classification-pipeline` | Tampering: blind the classification pipeline |  | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-purview-post-exploitation.md#dosbreak` | DoS/Break |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-purview-post-exploitation.md#references` | References |  | STRUCTURAL | section grouping heading |

## az-post-exploitation/az-queue-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-queue-post-exploitation.md#dataactions-microsoftstoragestorageaccountsqueueservicesqueuesmessagesread` | DataActions: `Microsoft.Storage/storageAccounts/queueServices/queues/messages/read` | Microsoft.Storage/storageAccounts/queueServices/queues/messages/read | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-queue-post-exploitation.md#dataactions-microsoftstoragestorageaccountsqueueservicesqueuesmessagesaddaction` | DataActions: `Microsoft.Storage/storageAccounts/queueServices/queues/messages/add/action` | Microsoft.Storage/storageAccounts/queueServices/queues/messages/add/action | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-queue-post-exploitation.md#actions-microsoftstoragestorageaccountsqueueservicesqueueswrite` | Actions: `Microsoft.Storage/storageAccounts/queueServices/queues/write` | Microsoft.Storage/storageAccounts/queueServices/queues/write | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-queue-post-exploitation.md#dataactions-microsoftstoragestorageaccountsqueueservicesqueuesmessageswrite` | DataActions: `Microsoft.Storage/storageAccounts/queueServices/queues/messages/write` | Microsoft.Storage/storageAccounts/queueServices/queues/messages/write | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-queue-post-exploitation.md#actions-microsoftstoragestorageaccountsqueueservicesqueuessetaclaction` | Actions: `Microsoft.Storage/storageAccounts/queueServices/queues/setAcl/action` | Microsoft.Storage/storageAccounts/queueServices/queues/setAcl/action | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-queue-post-exploitation.md#actions-microsoftstoragestorageaccountsqueueservicesqueuesdelete` | Actions: `Microsoft.Storage/storageAccounts/queueServices/queues/delete` | Microsoft.Storage/storageAccounts/queueServices/queues/delete | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-queue-post-exploitation.md#dataactions-microsoftstoragestorageaccountsqueueservicesqueuesmessagesdelete` | DataActions: `Microsoft.Storage/storageAccounts/queueServices/queues/messages/delete` | Microsoft.Storage/storageAccounts/queueServices/queues/messages/delete | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-queue-post-exploitation.md#dataactions-microsoftstoragestorageaccountsqueueservicesqueuesmessagesprocessaction` | DataActions: `Microsoft.Storage/storageAccounts/queueServices/queues/messages/process/action` | Microsoft.Storage/storageAccounts/queueServices/queues/messages/process/action | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-queue-post-exploitation.md` | Az - Queue Storage Post Exploitation |  | EXCLUDED | page reviewed: post-exploitation techniques; rows below |

## az-post-exploitation/az-redis-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-redis-post-exploitation.md#full-cache-exfiltration-with-microsoftcacheredisexportaction` | Full-cache exfiltration with `Microsoft.Cache/redis/export/action` | Microsoft.Cache/redis/export/action | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-redis-post-exploitation.md#cache-poisoning-with-microsoftcacheredisimportaction` | Cache poisoning with `Microsoft.Cache/redis/import/action` | Microsoft.Cache/redis/import/action | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-redis-post-exploitation.md#exposure-flips-with-microsoftcacherediswrite` | Exposure flips with `Microsoft.Cache/redis/write` | Microsoft.Cache/redis/write | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-redis-post-exploitation.md#open-the-data-plane-firewall-with-microsoftcacheredisfirewallruleswrite` | Open the data-plane firewall with `Microsoft.Cache/redis/firewallRules/write` | Microsoft.Cache/redis/firewallRules/write | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-redis-post-exploitation.md#control-plane-cache-wipe-with-microsoftcacheredisflushaction` | Control-plane cache wipe with `Microsoft.Cache/redis/flush/action` | Microsoft.Cache/redis/flush/action | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-redis-post-exploitation.md` | Az - Redis Post Exploitation |  | EXCLUDED | page reviewed: post-exploitation techniques; rows below |

## az-post-exploitation/az-sentinel-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-sentinel-post-exploitation.md#bypassing-sentinel-detections-operating-within-the-model` | Bypassing Sentinel detections (operating within the model) |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-sentinel-post-exploitation.md#auto-close-incidents-with-an-automation-rule` | Auto-close incidents with an automation rule |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-sentinel-post-exploitation.md#watchlist-poisoning` | Watchlist poisoning |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-sentinel-post-exploitation.md#disable-or-narrow-analytics-rules` | Disable or narrow analytics rules |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-sentinel-post-exploitation.md#delete--reassign-incidents` | Delete / reassign incidents |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-sentinel-post-exploitation.md#kill-the-data-connector` | Kill the data connector |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-sentinel-post-exploitation.md` | Az - Sentinel Post Exploitation |  | EXCLUDED | page reviewed: post-exploitation techniques; rows below |
| `az-post-exploitation/az-sentinel-post-exploitation.md#workspace-data-disclosure` | Workspace data disclosure |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-sentinel-post-exploitation.md#kql-over-sensitive-tables` | KQL over sensitive tables |  | EXCLUDED | Data read; any harvested secret is content-dependent and not derivable from RBAC. |

## az-post-exploitation/az-service-connector-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-service-connector-post-exploitation.md` |  |  | STRUCTURAL | page reviewed: data exfiltration, tampering, evasion and DoS; identity-relevant sections mapped/excluded per heading |
| `az-post-exploitation/az-service-connector-post-exploitation.md#read-connection-configuration-to-exfiltrate-the-backing-secret` | Read connection configuration to exfiltrate the backing secret | Microsoft.ServiceLinker/linkers/generateConfigurations/action,Microsoft.ServiceLinker/linkers/listConfigurations/action,Microsoft.ServiceLinker/linkers/read | EXCLUDED | Backing secret of a secret-auth connection; target-service data access, content-dependent. |

## az-post-exploitation/az-servicebus-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-servicebus-post-exploitation.md#actions-authorizationrules-send-and-receive-messages` | Actions: `AuthorizationRules` Send and Receive Messages |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-servicebus-post-exploitation.md#actions-microsoftservicebusnamespacesqueueswrite-microsoftservicebusnamespacesqueuesread` | Actions: `Microsoft.ServiceBus/namespaces/queues/write` (`Microsoft.ServiceBus/namespaces/queues/read`) | Microsoft.ServiceBus/namespaces/queues/write;Microsoft.ServiceBus/namespaces/queues/read | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-servicebus-post-exploitation.md#actions-microsoftservicebusnamespacestopicssubscriptionswrite-microsoftservicebusnamespacestopicssubscriptionsread` | Actions: `Microsoft.ServiceBus/namespaces/topics/subscriptions/write` (`Microsoft.ServiceBus/namespaces/topics/subscriptions/read`) | Microsoft.ServiceBus/namespaces/topics/subscriptions/write;Microsoft.ServiceBus/namespaces/topics/subscriptions/read | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-servicebus-post-exploitation.md#microsoftservicebusnamespacesnetworkrulesetswrite---network-lock-out--exposure` | `Microsoft.ServiceBus/namespaces/networkRuleSets/write` - Network lock-out / exposure | Microsoft.ServiceBus/namespaces/networkRuleSets/write | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-servicebus-post-exploitation.md#actions-microsoftservicebusnamespacesdelete` | Actions: `Microsoft.ServiceBus/namespaces/Delete` | Microsoft.ServiceBus/namespaces/Delete | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-servicebus-post-exploitation.md#actions-microsoftservicebusnamespacestopicsdelete` | Actions: `Microsoft.ServiceBus/namespaces/topics/Delete` | Microsoft.ServiceBus/namespaces/topics/Delete | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-servicebus-post-exploitation.md#actions-microsoftservicebusnamespacesqueuesdelete` | Actions: `Microsoft.ServiceBus/namespaces/queues/Delete` | Microsoft.ServiceBus/namespaces/queues/Delete | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-servicebus-post-exploitation.md#actions-microsoftservicebusnamespacestopicssubscriptionsdelete` | Actions: `Microsoft.ServiceBus/namespaces/topics/subscriptions/Delete` | Microsoft.ServiceBus/namespaces/topics/subscriptions/Delete | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-servicebus-post-exploitation.md#actions-microsoftservicebusnamespacestopicswrite-microsoftservicebusnamespacestopicsread` | Actions: `Microsoft.ServiceBus/namespaces/topics/write` (`Microsoft.ServiceBus/namespaces/topics/read`) | Microsoft.ServiceBus/namespaces/topics/write;Microsoft.ServiceBus/namespaces/topics/read | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-servicebus-post-exploitation.md#microsoftservicebusnamespacesdisasterrecoveryconfigswrite-failoveraction-breakpairingaction---geo-dr-failover--break-pairing-hijack` | `Microsoft.ServiceBus/namespaces/disasterRecoveryConfigs/write`, `.../failover/action`, `.../breakPairing/action` - Geo-DR failover / break-pairing hijack | Microsoft.ServiceBus/namespaces/disasterRecoveryConfigs/write | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-servicebus-post-exploitation.md#microsoftservicebusnamespaceswrite---disable-local-auth-lock-out-disablelocalauthtrue` | `Microsoft.ServiceBus/namespaces/write` - Disable local auth lock-out (`disableLocalAuth=true`) | Microsoft.ServiceBus/namespaces/write | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-servicebus-post-exploitation.md#customer-managed-key-cmk-revocation-dos` | Customer-managed key (CMK) revocation DoS |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-servicebus-post-exploitation.md` | Az - Service Bus Post Exploitation |  | EXCLUDED | page reviewed: post-exploitation techniques; rows below |

## az-post-exploitation/az-sql-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-sql-post-exploitation.md` |  |  | STRUCTURAL | page reviewed: data exfiltration, tampering, evasion and DoS; identity-relevant sections are covered by existing entries or excluded below |
| `az-post-exploitation/az-sql-post-exploitation.md#az---sql-database-post-exploitation` | Az - SQL Database Post Exploitation |  | STRUCTURAL | page title |
| `az-post-exploitation/az-sql-post-exploitation.md#sql` | SQL |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-sql-post-exploitation.md#microsoftsqllocationsconnectionpoliciesazureasyncoperationread-microsoftsqlserversconnectionpoliciesread--microsoftsqlserversconnectionpolicieswrite` | `Microsoft.Sql/locations/connectionPoliciesAzureAsyncOperation/read`, `Microsoft.Sql/servers/connectionPolicies/read` && `Microsoft.Sql/servers/connectionPolicies/write` | Microsoft.Sql/locations/connectionPoliciesAzureAsyncOperation/read,Microsoft.Sql/servers/connectionPolicies/read,Microsoft.Sql/servers/connectionPolicies/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-sql-post-exploitation.md#data-export` | Data export |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-sql-post-exploitation.md#microsoftsqlserversdatabasesread-microsoftsqlserversread--microsoftsqlserversdatabaseswrite` | `Microsoft.Sql/servers/databases/read`, `Microsoft.Sql/servers/read` && `Microsoft.Sql/servers/databases/write` | Microsoft.Sql/servers/databases/read,Microsoft.Sql/servers/databases/write,Microsoft.Sql/servers/read | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-sql-post-exploitation.md#microsoftsqlserversdatabasesexportaction` | `Microsoft.Sql/servers/databases/export/action` | Microsoft.Sql/servers/databases/export/action | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-sql-post-exploitation.md#microsoftsqlserversdatabaseswrite-createmode-secondarycopy--microsoftsqlserversfailovergroupswrite` | `Microsoft.Sql/servers/databases/write` (createMode Secondary/Copy) && `Microsoft.Sql/servers/failoverGroups/write` | Microsoft.Sql/servers/databases/read,Microsoft.Sql/servers/databases/replicationLinks/write,Microsoft.Sql/servers/databases/write,Microsoft.Sql/servers/failoverGroups/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-sql-post-exploitation.md#data-tampering` | Data tampering |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-sql-post-exploitation.md#microsoftsqlserversdatabasesimportaction` | `Microsoft.Sql/servers/databases/import/action` | Microsoft.Sql/servers/databases/import/action | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-sql-post-exploitation.md#sql-data-sync--attacker-controlled-sync-member-continuous-2-way-exfil--tamper` | SQL Data Sync — attacker-controlled sync member (continuous 2-way exfil + tamper) | Microsoft.Sql/servers/databases/syncGroups/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-sql-post-exploitation.md#security-control-bypass` | Security control bypass |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-sql-post-exploitation.md#microsoftsqlserversdatabasestransparentdataencryptionwrite-microsoftsqllocationstransparentdataencryptionazureasyncoperationread-microsoftsqlserversdatabasestransparentdataencryptionread` | `Microsoft.Sql/servers/databases/transparentDataEncryption/write`, `Microsoft.Sql/locations/transparentDataEncryptionAzureAsyncOperation/read`, `Microsoft.Sql/servers/databases/transparentDataEncryption/read` | Microsoft.Sql/locations/transparentDataEncryptionAzureAsyncOperation/read,Microsoft.Sql/servers/databases/transparentDataEncryption/read,Microsoft.Sql/servers/databases/transparentDataEncryption/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-sql-post-exploitation.md#telemetry-tampering` | Telemetry tampering |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-sql-post-exploitation.md#microsoftsqlserversauditingsettingsread--microsoftsqlserversauditingsettingswrite` | `Microsoft.Sql/servers/auditingSettings/read` && `Microsoft.Sql/servers/auditingSettings/write` | Microsoft.Sql/servers/auditingSettings/read,Microsoft.Sql/servers/auditingSettings/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-sql-post-exploitation.md#microsoftsqlserversadvancedthreatprotectionsettingswrite--microsoftsqlserverssecurityalertpolicieswrite` | `Microsoft.Sql/servers/advancedThreatProtectionSettings/write` && `Microsoft.Sql/servers/securityAlertPolicies/write` | Microsoft.Sql/servers/advancedThreatProtectionSettings/write,Microsoft.Sql/servers/securityAlertPolicies/write,Microsoft.Sql/servers/vulnerabilityAssessments/delete | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-sql-post-exploitation.md#complete-the-audit-teardown--extended--devops-auditing--diagnostic-settings` | Complete the audit teardown — extended / DevOps auditing + diagnostic settings | Microsoft.Insights/diagnosticSettings/write,Microsoft.Sql/servers/devOpsAuditingSettings/write,Microsoft.Sql/servers/extendedAuditingSettings/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-sql-post-exploitation.md#microsoftsqlserversdatabasesledgerdigestuploadsdisableaction-microsoftsqllocationsledgerdigestuploadsazureasyncoperationread-microsoftsqllocationsledgerdigestuploadsoperationresultsread` | `Microsoft.Sql/servers/databases/ledgerDigestUploads/disable/action`, `Microsoft.Sql/locations/ledgerDigestUploadsAzureAsyncOperation/read`, `Microsoft.Sql/locations/ledgerDigestUploadsOperationResults/read` | Microsoft.Sql/locations/ledgerDigestUploadsAzureAsyncOperation/read,Microsoft.Sql/locations/ledgerDigestUploadsOperationResults/read,Microsoft.Sql/servers/databases/ledgerDigestUploads/disable/action | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-sql-post-exploitation.md#dosbreak` | DoS/Break |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-sql-post-exploitation.md#microsoftsqlserverselasticpoolswrite--microsoftsqlserverselasticpoolsread` | `Microsoft.Sql/servers/elasticPools/write` && `Microsoft.Sql/servers/elasticPools/read` | Microsoft.Sql/servers/elasticPools/read,Microsoft.Sql/servers/elasticPools/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-sql-post-exploitation.md#microsoftsqlserverskeyswrite--microsoftsqlserverskeysread` | `Microsoft.Sql/servers/keys/write` && `Microsoft.Sql/servers/keys/read` | Microsoft.Sql/servers/keys/read,Microsoft.Sql/servers/keys/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-sql-post-exploitation.md#references` | References |  | STRUCTURAL | section grouping heading |

## az-post-exploitation/az-storage-mover-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-storage-mover-post-exploitation.md#repoint--define-a-job-to-exfiltrate-on-prem-shares-to-attacker-storage` | Repoint / define a job to exfiltrate on-prem shares to attacker storage |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-storage-mover-post-exploitation.md` | Az - Storage Mover Post Exploitation |  | EXCLUDED | page reviewed: post-exploitation techniques; rows below |

## az-post-exploitation/az-storage-tasks-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-storage-tasks-post-exploitation.md#recurrent-task-as-standing-managed-identity-backed-persistence` | Recurrent task as standing managed-identity-backed persistence |  | EXCLUDED | Task MI only performs the blob operations the task defines and needs roleAssignments/write for its data role; persistence/destruction, no token to the source. |
| `az-post-exploitation/az-storage-tasks-post-exploitation.md#blob-index-tag--classification-tampering-at-fleet-scale` | Blob index-tag / classification tampering at fleet scale |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-storage-tasks-post-exploitation.md#fleet-scale-destructive--ransomware-operations-from-one-object` | Fleet-scale destructive / ransomware operations from one object |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-storage-tasks-post-exploitation.md#fleet-wide-locked-immutability--legal-hold-lockout-extortion--ir-obstruction` | Fleet-wide locked-immutability / legal-hold lockout (extortion / IR obstruction) |  | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-storage-tasks-post-exploitation.md` | Az - Storage Tasks Post-Exploitation |  | EXCLUDED | page reviewed: post-exploitation techniques; rows below |

## az-post-exploitation/az-synapse-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-synapse-post-exploitation.md` |  |  | STRUCTURAL | page reviewed: data exfiltration, tampering, evasion and DoS; identity-relevant sections are covered by existing entries or excluded below |
| `az-post-exploitation/az-synapse-post-exploitation.md#az---synapse-post-exploitation` | Az - Synapse Post Exploitation |  | STRUCTURAL | page title |
| `az-post-exploitation/az-synapse-post-exploitation.md#azure-synapse-analytics` | Azure Synapse Analytics |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-synapse-post-exploitation.md#security-control-bypass` | Security control bypass |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-synapse-post-exploitation.md#network-boundary-weakening` | Network boundary weakening |  | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-synapse-post-exploitation.md#telemetry-tampering` | Telemetry tampering |  | STRUCTURAL | section grouping heading |
| `az-post-exploitation/az-synapse-post-exploitation.md#disable-sql-auditing--threat-detection-and-strip-data-masking` | Disable SQL auditing / threat detection and strip data masking | Microsoft.Synapse/workspaces/sqlPools/auditingSettings/write | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-synapse-post-exploitation.md#references` | References |  | STRUCTURAL | section grouping heading |

## az-post-exploitation/az-table-storage-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-table-storage-post-exploitation.md#microsoftstoragestorageaccountstableservicestablesread--microsoftstoragestorageaccountstableservicestablesentitiesread` | Microsoft.Storage/storageAccounts/tableServices/tables/read \| Microsoft.Storage/storageAccounts/tableServices/tables/entities/read | Microsoft.Storage/storageAccounts/tableServices/tables/read;Microsoft.Storage/storageAccounts/tableServices/tables/entities/read | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-table-storage-post-exploitation.md#microsoftstoragestorageaccountstableservicestablesentitieswrite--microsoftstoragestorageaccountstableservicestablesentitiesaddaction--microsoftstoragestorageaccountstableservicestablesentitiesupdateaction` | Microsoft.Storage/storageAccounts/tableServices/tables/entities/write \| Microsoft.Storage/storageAccounts/tableServices/tables/entities/add/action \| Microsoft.Storage/storageAccounts/tableServices/tables/entities/update/action | Microsoft.Storage/storageAccounts/tableServices/tables/entities/write;Microsoft.Storage/storageAccounts/tableServices/tables/entities/add/action;Microsoft.Storage/storageAccounts/tableServices/tables/entities/update/action | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-table-storage-post-exploitation.md#microsoftstoragestorageaccountstableservicestablesentitiesdelete` | Microsoft.Storage/storageAccounts/tableServices/tables/entities/delete | Microsoft.Storage/storageAccounts/tableServices/tables/entities/delete | EXCLUDED | Data read/tampering, DoS or telemetry tampering using access the source already holds; no other principal's privileges (rule 4). |
| `az-post-exploitation/az-table-storage-post-exploitation.md` | Az - Table Storage Post Exploitation |  | EXCLUDED | page reviewed: post-exploitation techniques; rows below |

## az-post-exploitation/az-trusted-signing-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-trusted-signing-post-exploitation.md` |  |  | STRUCTURAL | page reviewed: data exfiltration, tampering, evasion and DoS; identity-relevant sections mapped/excluded per heading |
| `az-post-exploitation/az-trusted-signing-post-exploitation.md#persistence--self-granted-signer--timestamps-that-outlive-revocation` | Persistence — self-granted Signer + timestamps that outlive revocation | Microsoft.Authorization/roleAssignments/write | EXCLUDED | Code-signing abuse; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-trusted-signing-post-exploitation.md#sign-arbitrary-malware-with-an-existing-trusted-profile-marquee` | Sign arbitrary malware with an existing trusted profile (marquee) | Microsoft.CodeSigning/certificateProfiles/Sign/action | EXCLUDED | Code-signing abuse; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-trusted-signing-post-exploitation.md#enroll-a-new-certificate-profile-for-signing-control-plane` | Enroll a new certificate profile for signing (control-plane) | Microsoft.CodeSigning/codeSigningAccounts/certificateProfiles/write | EXCLUDED | Code-signing abuse; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-trusted-signing-post-exploitation.md#control-the-publisher-identity-via-identity-validation` | Control the publisher identity via identity validation | Microsoft.CodeSigning/IdentityVerification/ | EXCLUDED | Code-signing abuse; no Azure/Entra principal is obtained. |

## az-post-exploitation/az-virtual-desktop-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-virtual-desktop-post-exploitation.md` |  |  | STRUCTURAL | page reviewed: data exfiltration, tampering, evasion and DoS; identity-relevant sections mapped/excluded per heading |
| `az-post-exploitation/az-virtual-desktop-post-exploitation.md#common-techniques` | Common techniques | Microsoft.DesktopVirtualization/applicationGroups/write | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-virtual-desktop-privesc.md#fleet-rce-via-applicationgroupsapplicationswrite-lolbin-commandlinearguments` |
| `az-post-exploitation/az-virtual-desktop-post-exploitation.md#fleet-rce-via-applicationgroupsapplicationswrite-lolbin-commandlinearguments` | Fleet RCE via `applicationgroups/applications/write` (LOLBIN `commandLineArguments`) | Microsoft.DesktopVirtualization/applicationgroups/applications/write | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-virtual-desktop-privesc.md#fleet-rce-via-applicationgroupsapplicationswrite-lolbin-commandlinearguments`, `az-privilege-escalation/az-virtual-desktop-privesc.md#fleet-rce-via-applicationgroupsapplicationswrite-lolbin-commandlinearguments` |
| `az-post-exploitation/az-virtual-desktop-post-exploitation.md#managed-identity-token-theft-on-the-session-host` | Managed-identity token theft on the session host | Microsoft.Compute/virtualMachines/runCommand/action | EXCLUDED | On-box outcome step; reaching paths are VM run-command/extension entries and azure-avd-application-write-session-host-rce. |
| `az-post-exploitation/az-virtual-desktop-post-exploitation.md#in-session-phishing-via-usersessionssendmessageaction` | In-session phishing via `usersessions/sendMessage/action` | Microsoft.DesktopVirtualization/hostpools/sessionhosts/usersessions/sendMessage/action | EXCLUDED | User phishing prompt; user-behaviour-dependent. |
| `az-post-exploitation/az-virtual-desktop-post-exploitation.md#control-plane-malicious-app-attach-registration-via-appattachpackageswrite` | Control-plane malicious App Attach registration via `appattachpackages/write` | Microsoft.DesktopVirtualization/appattachpackages/write | EXCLUDED | Publishing the package needs applicationgroups/applications/write, already modelled by azure-avd-application-write-session-host-rce. |
| `az-post-exploitation/az-virtual-desktop-post-exploitation.md#device-redirection-exfil-channel-via-hostpoolswrite-customrdpproperty` | Device-redirection exfil channel via `hostpools/write` (`customRdpProperty`) | Microsoft.DesktopVirtualization/hostpools/write | EXCLUDED | Network/traffic interception, exposure or DNS tampering; no Azure/Entra principal is obtained. |

## az-post-exploitation/az-virtual-network-manager-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-virtual-network-manager-post-exploitation.md` |  |  | STRUCTURAL | page reviewed: data exfiltration, tampering, evasion and DoS; identity-relevant sections mapped/excluded per heading |
| `az-post-exploitation/az-virtual-network-manager-post-exploitation.md#security-admin-alwaysallow-skeleton-key-scope-wide-nsg-bypass` | Security admin `AlwaysAllow` skeleton key (scope-wide NSG bypass) | Microsoft.Network/networkManagers/commit/action,Microsoft.Network/networkManagers/securityAdminConfigurations/write | EXCLUDED | Network/traffic interception, exposure or DNS tampering; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-virtual-network-manager-post-exploitation.md#connectivity-configuration-mass-peering-lateral-movement-fabric` | Connectivity-configuration mass peering (lateral-movement fabric) | Microsoft.Network/networkManagers/commit/action,Microsoft.Network/networkManagers/connectivityConfigurations/write | EXCLUDED | Network/traffic interception, exposure or DNS tampering; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-virtual-network-manager-post-exploitation.md#security-admin-deny--estate-wide-dos--segmentation-break` | Security admin `Deny` — estate-wide DoS / segmentation break |  | EXCLUDED | Network/traffic interception, exposure or DNS tampering; no Azure/Entra principal is obtained. |

## az-post-exploitation/az-vms-and-network-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-vms-and-network-post-exploitation.md` |  |  | STRUCTURAL | page reviewed: data exfiltration, tampering, evasion and DoS; identity-relevant sections mapped/excluded per heading |
| `az-post-exploitation/az-vms-and-network-post-exploitation.md#sensitive-information-in-vm-extensions--vm-applications` | Sensitive information in VM Extensions & VM Applications | Microsoft.Compute/galleries/applications/*/read | EXCLUDED | Data read of extension/image/disk contents; any credential is content-dependent. |
| `az-post-exploitation/az-vms-and-network-post-exploitation.md#harvest-boot-diagnostics-logs` | Harvest boot diagnostics logs | Microsoft.Compute/virtualMachines/retrieveBootDiagnosticsData/action | EXCLUDED | Data read of boot diagnostics; content-dependent. |
| `az-post-exploitation/az-vms-and-network-post-exploitation.md#sensitive-information-in-images` | Sensitive information in images | Microsoft.Compute/galleries/read | EXCLUDED | Data read of extension/image/disk contents; any credential is content-dependent. |
| `az-post-exploitation/az-vms-and-network-post-exploitation.md#sensitive-information-in-restore-points` | Sensitive information in restore points | Microsoft.Compute/disks/write,Microsoft.Compute/restorePointCollections/restorePoints/read | EXCLUDED | Data read of extension/image/disk contents; any credential is content-dependent. |
| `az-post-exploitation/az-vms-and-network-post-exploitation.md#sensitive-information-in-disks--snapshots` | Sensitive information in disks & snapshots | Microsoft.Compute/disks/write,Microsoft.Compute/snapshots/read | EXCLUDED | Data read of extension/image/disk contents; any credential is content-dependent. |
| `az-post-exploitation/az-vms-and-network-post-exploitation.md#capture-vm--image--cross-tenant-gallery-share-exfiltration` | Capture VM → image → cross-tenant gallery share (exfiltration) | Microsoft.Compute/galleries/share/action,Microsoft.Compute/virtualMachines/capture/action | EXCLUDED | Data exfiltration/tampering/evasion/DoS; no new Azure/Entra principal. |
| `az-post-exploitation/az-vms-and-network-post-exploitation.md#network-pivoting-nsg-rule--route-table-writes` | Network pivoting (NSG rule / route-table writes) | Microsoft.Network/networkSecurityGroups/securityRules/write,Microsoft.Network/routeTables/routes/write | EXCLUDED | Network/traffic interception, exposure or DNS tampering; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-vms-and-network-post-exploitation.md#control-plane-packet-capture-network-watcher-wiretap` | Control-plane packet capture (Network Watcher wiretap) | Microsoft.Network/networkWatchers/packetCaptures/write | EXCLUDED | Network/traffic interception, exposure or DNS tampering; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-vms-and-network-post-exploitation.md#private-dns-record-hijack-internal-mitm` | Private DNS record hijack (internal MITM) | Microsoft.Network/privateDnsZones/A/write | EXCLUDED | Network/traffic interception, exposure or DNS tampering; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-vms-and-network-post-exploitation.md#public-dns-subdomain-takeover-via-dangling-record-dnszonescnameawrite` | Public DNS subdomain takeover via dangling record (`dnszones/CNAME\|A/write`) | Microsoft.Network/dnsZones/*,Microsoft.Network/dnszones/CNAME/write | EXCLUDED | Network/traffic interception, exposure or DNS tampering; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-vms-and-network-post-exploitation.md#inbound-email-hijack-via-mx-rewrite-dnszonesmxwrite` | Inbound email hijack via MX rewrite (`dnszones/MX/write`) | Microsoft.Network/dnszones/MX/write | EXCLUDED | Network/traffic interception, exposure or DNS tampering; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-vms-and-network-post-exploitation.md#ns-delegation-hijack-of-a-subdomain-dnszonesnswrite` | NS delegation hijack of a subdomain (`dnszones/NS/write`) | Microsoft.Network/dnszones/NS/write | EXCLUDED | Network/traffic interception, exposure or DNS tampering; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-vms-and-network-post-exploitation.md#dns-private-resolver-forwarding-rule-tamper-dnsforwardingrulesetsforwardingruleswrite` | DNS Private Resolver forwarding-rule tamper (`dnsForwardingRulesets/forwardingRules/write`) | Microsoft.Network/dnsForwardingRulesets/forwardingRules/write | EXCLUDED | Network/traffic interception, exposure or DNS tampering; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-vms-and-network-post-exploitation.md#front-door--cdn-origin-repoint-edge-reverse-proxy-mitm-cdnprofilesorigingroupsoriginswrite` | Front Door / CDN origin repoint (edge reverse-proxy MITM) (`Cdn/profiles/origingroups/origins/write`) | Microsoft.Cdn/profiles/*,Microsoft.Cdn/profiles/endpoints/origins/write,Microsoft.Cdn/profiles/origingroups/origins/write | EXCLUDED | Network/traffic interception, exposure or DNS tampering; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-vms-and-network-post-exploitation.md#front-door-rules-engine-headerroute-rewrite-auth-header-backdoor--partial-mitm-cdnprofilesrulesetsruleswrite` | Front Door rules-engine header/route rewrite (auth-header backdoor / partial MITM) (`Cdn/profiles/rulesets/rules/write`) | Microsoft.Cdn/profiles/rulesets/rules/write | EXCLUDED | Network/traffic interception, exposure or DNS tampering; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-vms-and-network-post-exploitation.md#classic-front-door-v1-backend-pool-repoint--https-downgrade-networkfrontdoorsbackendpoolswrite` | Classic Front Door (v1) backend-pool repoint + HTTPS downgrade (`Network/frontDoors/backendPools/write`) | Microsoft.Network/*,Microsoft.Network/frontDoors/backendPools/write | EXCLUDED | Network/traffic interception, exposure or DNS tampering; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-vms-and-network-post-exploitation.md#application-gateway-backend-repoint--listener-tls-cert-swap-regional-l7-mitm-networkapplicationgatewayswrite` | Application Gateway backend repoint + listener TLS-cert swap (regional L7 MITM) (`Network/applicationGateways/write`) | Microsoft.Network/*,Microsoft.Network/applicationGateways/write | EXCLUDED | Network/traffic interception, exposure or DNS tampering; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-vms-and-network-post-exploitation.md#traffic-manager-endpoint-repoint-dns-level-traffic-steal-networktrafficmanagerprofilesexternalendpointswrite` | Traffic Manager endpoint repoint (DNS-level traffic steal) (`Network/trafficManagerProfiles/externalEndpoints/write`) | Microsoft.Network/trafficManagerProfiles/*,Microsoft.Network/trafficManagerProfiles/externalEndpoints/write | EXCLUDED | Network/traffic interception, exposure or DNS tampering; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-vms-and-network-post-exploitation.md#load-balancer-backendnat-rewrite-in-vnet-l4-redirect-networkloadbalancersbackendaddresspoolswrite` | Load Balancer backend/NAT rewrite (in-VNet L4 redirect) (`Network/loadBalancers/backendAddressPools/write`) | Microsoft.Network/loadBalancers/backendAddressPools/write | EXCLUDED | Network/traffic interception, exposure or DNS tampering; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-vms-and-network-post-exploitation.md#nic-ip-forwarding--in-vnet-mitm-router` | NIC IP forwarding → in-VNet MITM router | Microsoft.Network/networkInterfaces/write,Microsoft.Network/routeTables/routes/write | EXCLUDED | Network/traffic interception, exposure or DNS tampering; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-vms-and-network-post-exploitation.md#vm-application-pivoting` | VM Application Pivoting | Microsoft.Compute/galleries/applications/versions/write | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputegallerieswrite-microsoftcomputegalleriesapplicationswrite-microsoftcomputegalleriesapplicationsversionswrite-microsoftcomputevirtualmachineswrite` |
| `az-post-exploitation/az-vms-and-network-post-exploitation.md#domain-validated--acme-tls-cert-issuance-for-the-victim-domain-dnszonestxtacnamewrite` | Domain-validated / ACME TLS cert issuance for the victim domain (`dnszones/TXT\|A\|CNAME/write`) | Microsoft.Network/dnszones/TXT/write | EXCLUDED | Network/traffic interception, exposure or DNS tampering; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-vms-and-network-post-exploitation.md#outbound-mail-spoofing-via-spfdkimdmarc-txt-tamper-dnszonestxtwrite` | Outbound mail spoofing via SPF/DKIM/DMARC TXT tamper (`dnszones/TXT/write`) | Microsoft.Network/dnszones/TXT/write | EXCLUDED | Network/traffic interception, exposure or DNS tampering; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-vms-and-network-post-exploitation.md#foreign-tenant--saas-domain-verification-takeover-via-txt-dnszonestxtwrite` | Foreign-tenant / SaaS domain-verification takeover via TXT (`dnszones/TXT/write`) | Microsoft.Network/dnszones/TXT/write | EXCLUDED | Network/traffic interception, exposure or DNS tampering; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-vms-and-network-post-exploitation.md#link-a-private-link-dns-zone-to-a-vnet-without-the-target-record` | Link a Private Link DNS zone to a VNet without the target record | Microsoft.Network/privateDnsZones/virtualNetworkLinks/write,Microsoft.Network/virtualNetworks/join/action | EXCLUDED | Network/traffic interception, exposure or DNS tampering; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-vms-and-network-post-exploitation.md#disk-encryption-set--cmk-revocation-destruction-dos--extortion` | Disk Encryption Set / CMK revocation (destruction, DoS & extortion) | Microsoft.Compute/diskEncryptionSets/write,Microsoft.KeyVault/vaults/keys/ | EXCLUDED | Security-control weakening, telemetry tampering or DoS; no Azure/Entra principal is obtained. |

## az-post-exploitation/az-waf-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-waf-post-exploitation.md` |  |  | STRUCTURAL | page reviewed: data exfiltration, tampering, evasion and DoS; identity-relevant sections mapped/excluded per heading |
| `az-post-exploitation/az-waf-post-exploitation.md#turn-prevention-into-detection-or-off` | Turn Prevention into Detection (or Off) | Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/write,Microsoft.Network/frontdoorWebApplicationFirewallPolicies/write | EXCLUDED | Security-control weakening, telemetry tampering or DoS; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-waf-post-exploitation.md#exclusions-and-custom-rule-allow` | Exclusions and custom-rule allow | Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/write,Microsoft.Network/frontdoorWebApplicationFirewallPolicies/write | EXCLUDED | Security-control weakening, telemetry tampering or DoS; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-waf-post-exploitation.md#get-under-the-inspection-limits` | Get under the inspection limits |  | EXCLUDED | Security-control weakening, telemetry tampering or DoS; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-waf-post-exploitation.md#detach-the-waf-from-the-endpoint-front-door-security-policy-unbind` | Detach the WAF from the endpoint (Front Door security-policy unbind) | Microsoft.Cdn/profiles/securitypolicies/delete,Microsoft.Network/applicationGateways/write | EXCLUDED | Security-control weakening, telemetry tampering or DoS; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-waf-post-exploitation.md#application-gateway-for-containers-agc--waf-unbind--traffic-redirect` | Application Gateway for Containers (AGC) — WAF unbind / traffic redirect | Microsoft.ServiceNetworking/trafficControllers/securityPolicies/delete | EXCLUDED | Security-control weakening, telemetry tampering or DoS; no Azure/Entra principal is obtained. |
| `az-post-exploitation/az-waf-post-exploitation.md#cut-the-waf-logs` | Cut the WAF logs | Microsoft.Insights/diagnosticSettings/delete | EXCLUDED | Security-control weakening, telemetry tampering or DoS; no Azure/Entra principal is obtained. |

## az-services/az-acr.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-acr.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-advisor.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-advisor.md` | Az - Advisor |  | STRUCTURAL | page reviewed: service description / enumeration; techniques live on the privesc, post-exploitation and persistence pages |

## az-services/az-ai-foundry.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-ai-foundry.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration only; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-ai-search.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-ai-search.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration only; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-analysis-services.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-analysis-services.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration only; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-api-center.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-api-center.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration only; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-api-management.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-api-management.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-app-configuration.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-app-configuration.md` | Azure - App Configuration Enumeration |  | STRUCTURAL | page reviewed: service description / enumeration; techniques live on the privesc, post-exploitation and persistence pages |

## az-services/az-app-services.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-app-services.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-application-proxy.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-application-proxy.md` | (page) |  | STRUCTURAL | page reviewed: service description / enumeration |
| `az-services/az-application-proxy.md#az---application-proxy` | Az - Application Proxy |  | STRUCTURAL | title/reference/intro heading |
| `az-services/az-application-proxy.md#basic-information` | Basic Information |  | STRUCTURAL | title/reference/intro heading |
| `az-services/az-application-proxy.md#enumeration` | Enumeration |  | STRUCTURAL | title/reference/intro heading |
| `az-services/az-application-proxy.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-services/az-arc-enabled-servers.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-arc-enabled-servers.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-arc-resource-bridge.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-arc-resource-bridge.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-arm-templates.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-arm-templates.md` | Az - ARM Templates / Deployments |  | STRUCTURAL | page reviewed: service description / enumeration; techniques live on the privesc, post-exploitation and persistence pages |

## az-services/az-attestation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-attestation.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration only; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-automation-accounts.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-automation-accounts.md` | Az - Automation Accounts |  | STRUCTURAL | page reviewed: service description / enumeration; techniques live on the privesc, post-exploitation and persistence pages |

## az-services/az-azuread.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-azuread.md` | (page) |  | STRUCTURAL | page reviewed: service description / enumeration |
| `az-services/az-azuread.md#az---entra-id-azuread--azure-iam` | Az - Entra ID (AzureAD) & Azure IAM |  | STRUCTURAL | title/reference/intro heading |
| `az-services/az-azuread.md#basic-information` | Basic Information |  | STRUCTURAL | title/reference/intro heading |
| `az-services/az-azuread.md#enumeration` | Enumeration |  | STRUCTURAL | title/reference/intro heading |
| `az-services/az-azuread.md#connection` | **Connection** |  | EXCLUDED | service description / enumeration |
| `az-services/az-azuread.md#tenants` | Tenants |  | EXCLUDED | service description / enumeration |
| `az-services/az-azuread.md#users` | Users |  | EXCLUDED | service description / enumeration |
| `az-services/az-azuread.md#change-user-password` | Change User Password |  | SUBSECTION | of #users: EXCLUDED: service description / enumeration |
| `az-services/az-azuread.md#mfa--conditional-access-policies` | MFA & Conditional Access Policies |  | EXCLUDED | service description / enumeration |
| `az-services/az-azuread.md#groups` | Groups |  | EXCLUDED | service description / enumeration |
| `az-services/az-azuread.md#add-user-to-group` | Add user to group |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-entraid-privesc/README.md#add-user-to-group` |
| `az-services/az-azuread.md#service-principals` | Service Principals |  | EXCLUDED | service description / enumeration |
| `az-services/az-azuread.md#applications` | Applications |  | EXCLUDED | service description / enumeration |
| `az-services/az-azuread.md#managed-identities` | Managed Identities |  | EXCLUDED | service description / enumeration |
| `az-services/az-azuread.md#azure-roles` | Azure Roles |  | EXCLUDED | service description / enumeration |
| `az-services/az-azuread.md#entra-id-roles` | Entra ID Roles |  | EXCLUDED | service description / enumeration |
| `az-services/az-azuread.md#devices` | Devices |  | EXCLUDED | service description / enumeration |
| `az-services/az-azuread.md#administrative-units` | Administrative Units |  | EXCLUDED | service description / enumeration |
| `az-services/az-azuread.md#microsoft-graph-delegated-sharepoint-data-exfiltration-sharepointdumper` | Microsoft Graph delegated SharePoint data exfiltration (SharePointDumper) |  | EXCLUDED | service description / enumeration |
| `az-services/az-azuread.md#obtaining-usable-delegated-tokens` | Obtaining usable delegated tokens |  | SUBSECTION | of #microsoft-graph-delegated-sharepoint-data-exfiltration-sharepointdumper: EXCLUDED: service description / enumeration |
| `az-services/az-azuread.md#running-sharepointdumper-for-enumeration--exfiltration` | Running SharePointDumper for enumeration + exfiltration |  | SUBSECTION | of #microsoft-graph-delegated-sharepoint-data-exfiltration-sharepointdumper: EXCLUDED: service description / enumeration |
| `az-services/az-azuread.md#entra-id-privilege-escalation` | Entra ID Privilege Escalation |  | EXCLUDED | service description / enumeration |
| `az-services/az-azuread.md#azure-privilege-escalation` | Azure Privilege Escalation |  | EXCLUDED | service description / enumeration |
| `az-services/az-azuread.md#defensive-mechanisms` | Defensive Mechanisms |  | EXCLUDED | service description / enumeration |
| `az-services/az-azuread.md#privileged-identity-management-pim` | Privileged Identity Management (PIM) |  | SUBSECTION | of #defensive-mechanisms: EXCLUDED: service description / enumeration |
| `az-services/az-azuread.md#conditional-access-policies` | Conditional Access Policies |  | SUBSECTION | of #defensive-mechanisms: EXCLUDED: service description / enumeration |
| `az-services/az-azuread.md#entra-identity-protection` | Entra Identity Protection |  | SUBSECTION | of #defensive-mechanisms: EXCLUDED: service description / enumeration |
| `az-services/az-azuread.md#entra-password-protection` | Entra Password Protection |  | SUBSECTION | of #defensive-mechanisms: EXCLUDED: service description / enumeration |
| `az-services/az-azuread.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-services/az-backup-and-recovery-services.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-backup-and-recovery-services.md` | Azure - Backup and Recovery Services Enumeration |  | STRUCTURAL | page reviewed: service description / enumeration; techniques live on the privesc, post-exploitation and persistence pages |

## az-services/az-batch.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-batch.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-bot-service.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-bot-service.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration only; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-chaos-studio.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-chaos-studio.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-cloud-shell.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-cloud-shell.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-cognitive-services-openai.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-cognitive-services-openai.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration only; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-communication-services.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-communication-services.md` | Azure - Communication Services Enumeration |  | STRUCTURAL | page reviewed: service description / enumeration; techniques live on the privesc, post-exploitation and persistence pages |

## az-services/az-confidential-ledger.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-confidential-ledger.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration only; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-container-instances-apps-jobs.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-container-instances-apps-jobs.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-container-registry.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-container-registry.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-cosmosDB.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-cosmosDB.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration only; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-cost-management.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-cost-management.md` | Az - Cost Management |  | STRUCTURAL | page reviewed: service description / enumeration; techniques live on the privesc, post-exploitation and persistence pages |

## az-services/az-data-explorer.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-data-explorer.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration only; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-data-factory.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-data-factory.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration only; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-data-share.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-data-share.md` | Azure - Data Share Enumeration |  | STRUCTURAL | page reviewed: service description / enumeration; techniques live on the privesc, post-exploitation and persistence pages |

## az-services/az-database-migration-service.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-database-migration-service.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration only; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-databricks.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-databricks.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration only; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-ddos-protection.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-ddos-protection.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-defender-easm.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-defender-easm.md` | Az - Defender EASM |  | STRUCTURAL | page reviewed: service description / enumeration; techniques live on the privesc, post-exploitation and persistence pages |

## az-services/az-defender-for-cloud.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-defender-for-cloud.md` | Az - Defender for Cloud |  | STRUCTURAL | page reviewed: service description / enumeration; techniques live on the privesc, post-exploitation and persistence pages |

## az-services/az-deployment-stacks.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-deployment-stacks.md` | Azure - Deployment Stacks Enumeration |  | STRUCTURAL | page reviewed: service description / enumeration; techniques live on the privesc, post-exploitation and persistence pages |

## az-services/az-dev-center.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-dev-center.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-devops.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-devops.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-devtest-labs.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-devtest-labs.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-digital-twins.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-digital-twins.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration only; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-elastic-san.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-elastic-san.md` | Azure - Elastic SAN Enumeration |  | STRUCTURAL | page reviewed: service description / enumeration; techniques live on the privesc, post-exploitation and persistence pages |

## az-services/az-entra-id-governance.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-entra-id-governance.md` | (page) |  | STRUCTURAL | page reviewed: service description / enumeration |
| `az-services/az-entra-id-governance.md#azure---entra-id-governance-enumeration` | Azure - Entra ID Governance Enumeration |  | STRUCTURAL | title/reference/intro heading |
| `az-services/az-entra-id-governance.md#enumerate-entitlement-management` | Enumerate entitlement management |  | EXCLUDED | service description / enumeration |
| `az-services/az-entra-id-governance.md#what-to-review` | What to review |  | EXCLUDED | service description / enumeration |
| `az-services/az-entra-id-governance.md#attack-techniques` | Attack techniques |  | EXCLUDED | service description / enumeration |
| `az-services/az-entra-id-governance.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-services/az-entra-id-logs.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-entra-id-logs.md` | (page) |  | STRUCTURAL | page reviewed: service description / enumeration |
| `az-services/az-entra-id-logs.md#az---entra-id-logs--monitoring` | Az - Entra ID Logs & Monitoring |  | STRUCTURAL | title/reference/intro heading |
| `az-services/az-entra-id-logs.md#entra-id---logs` | Entra ID - Logs |  | EXCLUDED | service description / enumeration |
| `az-services/az-entra-id-logs.md#entra-id---log-systems` | Entra ID - Log Systems |  | EXCLUDED | service description / enumeration |
| `az-services/az-entra-id-logs.md#graph-vs-arm-logging-visibility-useful-for-opsechunting` | Graph vs ARM logging visibility (useful for OPSEC/hunting) |  | EXCLUDED | service description / enumeration |
| `az-services/az-entra-id-logs.md#enumeration` | Enumeration |  | STRUCTURAL | title/reference/intro heading |
| `az-services/az-entra-id-logs.md#post-exploitation` | Post Exploitation |  | EXCLUDED | service description / enumeration |
| `az-services/az-entra-id-logs.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-services/az-entra-id-protection.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-entra-id-protection.md` | (page) |  | STRUCTURAL | page reviewed: service description / enumeration |
| `az-services/az-entra-id-protection.md#az---entra-id-protection` | Az - Entra ID Protection |  | STRUCTURAL | title/reference/intro heading |
| `az-services/az-entra-id-protection.md#basic-information` | Basic Information |  | STRUCTURAL | title/reference/intro heading |
| `az-services/az-entra-id-protection.md#licensing-decides-what-you-face` | Licensing decides what you face |  | EXCLUDED | service description / enumeration |
| `az-services/az-entra-id-protection.md#risk-detections` | Risk detections |  | EXCLUDED | service description / enumeration |
| `az-services/az-entra-id-protection.md#risk-remediation` | Risk remediation |  | EXCLUDED | service description / enumeration |
| `az-services/az-entra-id-protection.md#enumeration` | Enumeration |  | STRUCTURAL | title/reference/intro heading |
| `az-services/az-entra-id-protection.md#post-exploitation` | Post Exploitation |  | EXCLUDED | service description / enumeration |
| `az-services/az-entra-id-protection.md#persistence` | Persistence |  | EXCLUDED | service description / enumeration |
| `az-services/az-entra-id-protection.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-services/az-event-grid.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-event-grid.md` | Azure - Event Grid Enumeration |  | STRUCTURAL | page reviewed: service description / enumeration; techniques live on the privesc, post-exploitation and persistence pages |

## az-services/az-event-hubs.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-event-hubs.md` | Azure - Event Hubs Enumeration |  | STRUCTURAL | page reviewed: service description / enumeration; techniques live on the privesc, post-exploitation and persistence pages |

## az-services/az-fabric.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-fabric.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration only; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-file-shares.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-file-shares.md` | Az - File Shares |  | STRUCTURAL | page reviewed: service description / enumeration; techniques live on the privesc, post-exploitation and persistence pages |

## az-services/az-firewall.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-firewall.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-fluid-relay.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-fluid-relay.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration only; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-front-door.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-front-door.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-function-apps.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-function-apps.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-guest-configuration.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-guest-configuration.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-hdinsight.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-hdinsight.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration only; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-healthcare-apis.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-healthcare-apis.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration only; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-image-builder.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-image-builder.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-iot-hub.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-iot-hub.md` | Azure - IoT Hub Enumeration |  | STRUCTURAL | page reviewed: service description / enumeration; techniques live on the privesc, post-exploitation and persistence pages |

## az-services/az-keyvault.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-keyvault.md` | Az - Key Vault |  | STRUCTURAL | page reviewed: service description / enumeration; techniques live on the privesc, post-exploitation and persistence pages |

## az-services/az-kubernetes.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-kubernetes.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-load-testing.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-load-testing.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration only; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-log-analytics.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-log-analytics.md` | Az - Log Analytics |  | STRUCTURAL | page reviewed: service description / enumeration; techniques live on the privesc, post-exploitation and persistence pages |

## az-services/az-logic-apps.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-logic-apps.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-machine-learning.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-machine-learning.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration only; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-maintenance-and-update-manager.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-maintenance-and-update-manager.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-managed-applications.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-managed-applications.md` | Azure - Managed Applications Enumeration |  | STRUCTURAL | page reviewed: service description / enumeration; techniques live on the privesc, post-exploitation and persistence pages |

## az-services/az-managed-devops-pools.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-managed-devops-pools.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-managed-grafana.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-managed-grafana.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration only; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-management-groups-subscriptions-and-resource-groups.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-management-groups-subscriptions-and-resource-groups.md` | Az - Management Groups, Subscriptions & Resource Groups |  | STRUCTURAL | page reviewed: service description / enumeration; techniques live on the privesc, post-exploitation and persistence pages |

## az-services/az-maps.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-maps.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration only; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-migrate.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-migrate.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-misc.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-misc.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-monitor.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-monitor.md` | Az - Azure Monitor |  | STRUCTURAL | page reviewed: service description / enumeration; techniques live on the privesc, post-exploitation and persistence pages |

## az-services/az-mysql.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-mysql.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration only; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-netapp-files.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-netapp-files.md` | Azure - Azure NetApp Files Enumeration |  | STRUCTURAL | page reviewed: service description / enumeration; techniques live on the privesc, post-exploitation and persistence pages |

## az-services/az-notification-hubs.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-notification-hubs.md` | Azure - Notification Hubs Enumeration |  | STRUCTURAL | page reviewed: service description / enumeration; techniques live on the privesc, post-exploitation and persistence pages |

## az-services/az-pim.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-pim.md` | (page) |  | STRUCTURAL | page reviewed: service description / enumeration |
| `az-services/az-pim.md#az---privileged-identity-management-pim` | Az - Privileged Identity Management (PIM) |  | STRUCTURAL | title/reference/intro heading |
| `az-services/az-pim.md#basic-information` | Basic Information |  | STRUCTURAL | title/reference/intro heading |
| `az-services/az-pim.md#the-two-things-pim-is-to-an-attacker` | The two things PIM is, to an attacker |  | EXCLUDED | service description / enumeration |
| `az-services/az-pim.md#key-objects-graph` | Key objects (Graph) |  | EXCLUDED | service description / enumeration |
| `az-services/az-pim.md#enumeration` | Enumeration |  | STRUCTURAL | title/reference/intro heading |
| `az-services/az-pim.md#privilege-escalation` | Privilege Escalation |  | EXCLUDED | service description / enumeration |
| `az-services/az-pim.md#post-exploitation` | Post Exploitation |  | EXCLUDED | service description / enumeration |
| `az-services/az-pim.md#persistence` | Persistence |  | EXCLUDED | service description / enumeration |
| `az-services/az-pim.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-services/az-playwright-workspaces.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-playwright-workspaces.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-policy.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-policy.md` | Az - Azure Policy |  | STRUCTURAL | page reviewed: service description / enumeration; techniques live on the privesc, post-exploitation and persistence pages |

## az-services/az-postgresql.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-postgresql.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration only; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-power-pages.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-power-pages.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration only; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-purview.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-purview.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration only; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-quantum.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-quantum.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration only; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-queue.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-queue.md` | Az - Queue Storage |  | STRUCTURAL | page reviewed: service description / enumeration; techniques live on the privesc, post-exploitation and persistence pages |

## az-services/az-redis.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-redis.md` | Azure - Azure Cache for Redis Enumeration |  | STRUCTURAL | page reviewed: service description / enumeration; techniques live on the privesc, post-exploitation and persistence pages |

## az-services/az-relay.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-relay.md` | Azure - Azure Relay Enumeration |  | STRUCTURAL | page reviewed: service description / enumeration; techniques live on the privesc, post-exploitation and persistence pages |

## az-services/az-sentinel.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-sentinel.md` | Az - Sentinel |  | STRUCTURAL | page reviewed: service description / enumeration; techniques live on the privesc, post-exploitation and persistence pages |

## az-services/az-service-connector.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-service-connector.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-service-fabric.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-service-fabric.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-servicebus.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-servicebus.md` | Az - Service Bus Enum |  | STRUCTURAL | page reviewed: service description / enumeration; techniques live on the privesc, post-exploitation and persistence pages |

## az-services/az-signalr-web-pubsub.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-signalr-web-pubsub.md` | Azure - SignalR and Web PubSub Enumeration |  | STRUCTURAL | page reviewed: service description / enumeration; techniques live on the privesc, post-exploitation and persistence pages |

## az-services/az-speech-services.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-speech-services.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration only; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-spring-apps.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-spring-apps.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-sql.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-sql.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration only; attack techniques link to the privesc/post-exploitation/persistence pages; server MI usable from T-SQL only for external data sources (partial identity use, not modelled) |

## az-services/az-sre-agent.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-sre-agent.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration only; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-static-web-apps.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-static-web-apps.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-storage-mover.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-storage-mover.md` | Azure - Storage Mover Enumeration |  | STRUCTURAL | page reviewed: service description / enumeration; techniques live on the privesc, post-exploitation and persistence pages |

## az-services/az-storage-tasks.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-storage-tasks.md` | Azure - Storage Tasks Enumeration |  | STRUCTURAL | page reviewed: service description / enumeration; techniques live on the privesc, post-exploitation and persistence pages |

## az-services/az-storage.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-storage.md` | Az - Storage Accounts & Blobs |  | STRUCTURAL | page reviewed: service description / enumeration; techniques live on the privesc, post-exploitation and persistence pages |

## az-services/az-stream-analytics.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-stream-analytics.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration only; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-synapse.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-synapse.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration only; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-table-storage.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-table-storage.md` | Az - Table Storage |  | STRUCTURAL | page reviewed: service description / enumeration; techniques live on the privesc, post-exploitation and persistence pages |

## az-services/az-trusted-signing.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-trusted-signing.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-video-indexer.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-video-indexer.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration only; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-virtual-desktop.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-virtual-desktop.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-virtual-network-manager.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-virtual-network-manager.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-vmware-solution-avs.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-vmware-solution-avs.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/az-waf.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/az-waf.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/intune.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/intune.md` | (page) |  | STRUCTURAL | page reviewed: service description / enumeration |
| `az-services/intune.md#az---intune` | Az - Intune |  | STRUCTURAL | title/reference/intro heading |
| `az-services/intune.md#basic-information` | Basic Information |  | STRUCTURAL | title/reference/intro heading |
| `az-services/intune.md#attack-techniques` | Attack Techniques |  | EXCLUDED | service description / enumeration |
| `az-services/intune.md#privilege-escalation` | Privilege Escalation |  | SUBSECTION | of #attack-techniques: EXCLUDED: service description / enumeration |
| `az-services/intune.md#post-exploitation` | Post Exploitation |  | SUBSECTION | of #attack-techniques: EXCLUDED: service description / enumeration |
| `az-services/intune.md#persistence` | Persistence |  | SUBSECTION | of #attack-techniques: EXCLUDED: service description / enumeration |
| `az-services/intune.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-services/vms/README.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/vms/README.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-services/vms/az-azure-network.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-services/vms/az-azure-network.md` |  |  | STRUCTURAL | page reviewed: service overview and enumeration; attack techniques link to the privesc/post-exploitation/persistence pages |

## az-unauthenticated-enum-and-initial-entry/README.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-unauthenticated-enum-and-initial-entry/README.md` | (page) |  | STRUCTURAL | page reviewed: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/README.md#az---unauthenticated-enum--initial-entry` | Az - Unauthenticated Enum & Initial Entry |  | STRUCTURAL | title/reference/intro heading |
| `az-unauthenticated-enum-and-initial-entry/README.md#azure` | Azure |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/README.md#technique-categories` | Technique categories |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/README.md#public-reconnaissance` | Public reconnaissance |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/README.md#tenant-enumeration` | Tenant Enumeration |  | SUBSECTION | of #public-reconnaissance: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/README.md#user-enumeration` | User Enumeration |  | SUBSECTION | of #public-reconnaissance: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/README.md#password-spraying--brute-force` | Password Spraying / Brute-Force |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/README.md#resource-bruteforce-or-takeover` | Resource bruteforce or takeover |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/README.md#user-chosen-service-names` | User-chosen service names |  | SUBSECTION | of #resource-bruteforce-or-takeover: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/README.md#azure-unauthenticated-enum--access-per-service` | Azure Unauthenticated Enum & Access per service |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/README.md#phishing` | Phishing |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/README.md#authentication-and-access-control-bypass` | Authentication and access-control bypass |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/README.md#exchange-online-direct-to-tenant-smtp-spoofing` | Exchange Online direct-to-tenant SMTP spoofing |  | SUBSECTION | of #authentication-and-access-control-bypass: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/README.md#potential-credential-leaks` | Potential credential leaks |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/README.md#local-azure-identity-caches` | Local Azure identity caches |  | SUBSECTION | of #potential-credential-leaks: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/README.md#identity-token-candidates` | Identity-token candidates |  | SUBSECTION | of #potential-credential-leaks: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/README.md#application-secret-assignments` | Application-secret assignments |  | SUBSECTION | of #potential-credential-leaks: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/README.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-unauthenticated-enum-and-initial-entry/az-aks-kubernetes-unauth.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-unauthenticated-enum-and-initial-entry/az-aks-kubernetes-unauth.md` | (page) |  | STRUCTURAL | page reviewed: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-aks-kubernetes-unauth.md#az---aks--kubernetes-unauth` | Az - AKS / Kubernetes Unauth |  | STRUCTURAL | title/reference/intro heading |
| `az-unauthenticated-enum-and-initial-entry/az-aks-kubernetes-unauth.md#aks--kubernetes` | AKS / Kubernetes |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-aks-kubernetes-unauth.md#publicly-shared-data` | Publicly shared data |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-aks-kubernetes-unauth.md#public-api-server-discovery--version-disclosure` | Public API server discovery & version disclosure |  | SUBSECTION | of #publicly-shared-data: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-aks-kubernetes-unauth.md#anonymous-kubelet-metadata-disclosure` | Anonymous kubelet metadata disclosure |  | SUBSECTION | of #publicly-shared-data: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-aks-kubernetes-unauth.md#anonymous-acr-image-pull-cross-reference` | Anonymous ACR image pull (cross-reference) |  | SUBSECTION | of #publicly-shared-data: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-aks-kubernetes-unauth.md#anonymous-kubernetes-resource-reads` | Anonymous Kubernetes resource reads |  | SUBSECTION | of #publicly-shared-data: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-aks-kubernetes-unauth.md#anonymous-invocation-and-modification` | Anonymous invocation and modification |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-aks-kubernetes-unauth.md#anonymous-privileged-api-operations` | Anonymous privileged API operations |  | SUBSECTION | of #anonymous-invocation-and-modification: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-aks-kubernetes-unauth.md#exposed-kubernetes-dashboard` | Exposed Kubernetes Dashboard |  | SUBSECTION | of #anonymous-invocation-and-modification: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-aks-kubernetes-unauth.md#anonymous-privileged-kubelet-operations` | Anonymous privileged kubelet operations |  | SUBSECTION | of #anonymous-invocation-and-modification: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-aks-kubernetes-unauth.md#potential-credential-leaks` | Potential credential leaks |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-aks-kubernetes-unauth.md#kubeconfig-credentials` | Kubeconfig credentials |  | SUBSECTION | of #potential-credential-leaks: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-aks-kubernetes-unauth.md#bearer-identity-tokens` | Bearer identity tokens |  | SUBSECTION | of #potential-credential-leaks: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-aks-kubernetes-unauth.md#exposed-workloads--imds-ssrf--azure-managed-identity-token` | Exposed workloads → IMDS SSRF → Azure managed-identity token |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-aks-kubernetes-unauth.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-unauthenticated-enum-and-initial-entry/az-api-management-unauth.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-unauthenticated-enum-and-initial-entry/az-api-management-unauth.md` | (page) |  | STRUCTURAL | page reviewed: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-api-management-unauth.md#az---api-management-unauth` | Az - API Management Unauth |  | STRUCTURAL | title/reference/intro heading |
| `az-unauthenticated-enum-and-initial-entry/az-api-management-unauth.md#api-management` | API Management |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-api-management-unauth.md#publicly-shared-data` | Publicly shared data |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-api-management-unauth.md#public-developer-portal-documentation` | Public developer-portal documentation |  | SUBSECTION | of #publicly-shared-data: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-api-management-unauth.md#anonymous-invocation-and-modification` | Anonymous invocation and modification |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-api-management-unauth.md#open-products-without-subscription-keys` | Open products without subscription keys |  | SUBSECTION | of #anonymous-invocation-and-modification: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-api-management-unauth.md#potential-credential-leaks` | Potential credential leaks |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-api-management-unauth.md#apim-subscription-keys` | APIM subscription keys |  | SUBSECTION | of #potential-credential-leaks: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-api-management-unauth.md#self-registration-and-guest-access` | Self-registration and guest access |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-api-management-unauth.md#signup-bypass-even-when-registration-is-disabled` | `/signup` bypass even when registration is "disabled" |  | SUBSECTION | of #self-registration-and-guest-access: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-api-management-unauth.md#developer-portal-self-registration` | Developer-portal self-registration |  | SUBSECTION | of #self-registration-and-guest-access: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-api-management-unauth.md#authentication-and-access-control-bypass` | Authentication and access-control bypass |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-api-management-unauth.md#cors--backend-disclosure--direct-origin-bypass` | CORS / backend disclosure / direct-origin bypass |  | SUBSECTION | of #authentication-and-access-control-bypass: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-api-management-unauth.md#resource-bruteforce-or-takeover` | Resource bruteforce or takeover |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-api-management-unauth.md#subdomain--name-enumeration-dns-existence-oracle` | Subdomain / name enumeration (DNS existence oracle) |  | SUBSECTION | of #resource-bruteforce-or-takeover: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-api-management-unauth.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-unauthenticated-enum-and-initial-entry/az-app-services-functions-unauth.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-unauthenticated-enum-and-initial-entry/az-app-services-functions-unauth.md` | (page) |  | STRUCTURAL | page reviewed: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-app-services-functions-unauth.md#az---app-service--functions-unauth` | Az - App Service & Functions Unauth |  | STRUCTURAL | title/reference/intro heading |
| `az-unauthenticated-enum-and-initial-entry/az-app-services-functions-unauth.md#app-service--functions` | App Service & Functions |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-app-services-functions-unauth.md#publicly-shared-data` | Publicly shared data |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-app-services-functions-unauth.md#public-deployment-packages` | Public deployment packages |  | SUBSECTION | of #publicly-shared-data: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-app-services-functions-unauth.md#source--secrets-served-as-static-content` | Source / secrets served as static content |  | EXCLUDED | Strict principal-boundary audit: the catalog has no verified active principal or permission-gain path for this heading. |
| `az-unauthenticated-enum-and-initial-entry/az-app-services-functions-unauth.md#anonymous-invocation-and-modification` | Anonymous invocation and modification |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-app-services-functions-unauth.md#anonymous-http-triggered-functions` | Anonymous HTTP-triggered functions |  | SUBSECTION | of #anonymous-invocation-and-modification: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-app-services-functions-unauth.md#related-public-ingress-paas-container-apps-static-web-apps` | Related public-ingress PaaS (Container Apps, Static Web Apps) |  | SUBSECTION | of #anonymous-invocation-and-modification: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-app-services-functions-unauth.md#potential-credential-leaks` | Potential credential leaks |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-app-services-functions-unauth.md#publishingdeployment-credentials` | Publishing/deployment credentials |  | EXCLUDED | Detection regex and publishing context only; a format match does not prove a usable credential or bound target identity. |
| `az-unauthenticated-enum-and-initial-entry/az-app-services-functions-unauth.md#function-host-and-master-keys` | Function, host and master keys |  | SUBSECTION | of #potential-credential-leaks: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-app-services-functions-unauth.md#azure-sas-urlstokens` | Azure SAS URLs/tokens |  | SUBSECTION | of #potential-credential-leaks: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-app-services-functions-unauth.md#resource-bruteforce-or-takeover` | Resource bruteforce or takeover |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-app-services-functions-unauth.md#dangling-cname-subdomain-takeover` | Dangling-CNAME subdomain takeover |  | SUBSECTION | of #resource-bruteforce-or-takeover: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-app-services-functions-unauth.md#hostname--name-existence-enumeration` | Hostname / name-existence enumeration |  | SUBSECTION | of #resource-bruteforce-or-takeover: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-app-services-functions-unauth.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-unauthenticated-enum-and-initial-entry/az-automation-webhooks-unauth.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-unauthenticated-enum-and-initial-entry/az-automation-webhooks-unauth.md` | (page) |  | STRUCTURAL | page reviewed: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-automation-webhooks-unauth.md#az---automation-runbook-webhooks-unauth` | Az - Automation Runbook Webhooks Unauth |  | STRUCTURAL | title/reference/intro heading |
| `az-unauthenticated-enum-and-initial-entry/az-automation-webhooks-unauth.md#automation-runbook-webhooks` | Automation Runbook Webhooks |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-automation-webhooks-unauth.md#potential-credential-leaks` | Potential credential leaks |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-automation-webhooks-unauth.md#automation-webhook-urls` | Automation webhook URLs |  | SUBSECTION | of #potential-credential-leaks: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-automation-webhooks-unauth.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-unauthenticated-enum-and-initial-entry/az-blob-public-unauth.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-unauthenticated-enum-and-initial-entry/az-blob-public-unauth.md` | (page) |  | STRUCTURAL | page reviewed: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-blob-public-unauth.md#az---public-blob-and-static-website-access` | Az - Public blob and static website access |  | STRUCTURAL | title/reference/intro heading |
| `az-unauthenticated-enum-and-initial-entry/az-blob-public-unauth.md#blob-storage-and-static-websites` | Blob Storage and static websites |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-blob-public-unauth.md#publicly-shared-data` | Publicly shared data |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-blob-public-unauth.md#static-website-web-exposure--leaked-secrets` | Static website (`$web`) exposure & leaked secrets |  | SUBSECTION | of #publicly-shared-data: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-blob-public-unauth.md#anonymous-blob-listing-and-downloads` | Anonymous blob listing and downloads |  | SUBSECTION | of #publicly-shared-data: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-blob-public-unauth.md#auditing-anonymous-blob-exposure` | Auditing anonymous blob exposure |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-blob-public-unauth.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-unauthenticated-enum-and-initial-entry/az-cognitive-services-openai-unauth.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-unauthenticated-enum-and-initial-entry/az-cognitive-services-openai-unauth.md` | (page) |  | STRUCTURAL | page reviewed: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-cognitive-services-openai-unauth.md#az---cognitive-services--azure-openai-unauth` | Az - Cognitive Services / Azure OpenAI Unauth |  | STRUCTURAL | title/reference/intro heading |
| `az-unauthenticated-enum-and-initial-entry/az-cognitive-services-openai-unauth.md#cognitive-services--azure-openai` | Cognitive Services / Azure OpenAI |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-cognitive-services-openai-unauth.md#potential-credential-leaks` | Potential credential leaks |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-cognitive-services-openai-unauth.md#service-api-keys` | Service API keys |  | SUBSECTION | of #potential-credential-leaks: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-cognitive-services-openai-unauth.md#azure-ai-search-keys` | Azure AI Search keys |  | SUBSECTION | of #potential-credential-leaks: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-cognitive-services-openai-unauth.md#authentication-and-access-control-bypass` | Authentication and access-control bypass |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-cognitive-services-openai-unauth.md#prompt-injection-against-a-public-ai-chatbot-unauth-via-the-app` | Prompt injection against a public AI chatbot (unauth via the app) |  | SUBSECTION | of #authentication-and-access-control-bypass: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-cognitive-services-openai-unauth.md#resource-bruteforce-or-takeover` | Resource bruteforce or takeover |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-cognitive-services-openai-unauth.md#resource-name--existence-enumeration-via-dns` | Resource name / existence enumeration via DNS |  | SUBSECTION | of #resource-bruteforce-or-takeover: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-cognitive-services-openai-unauth.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-unauthenticated-enum-and-initial-entry/az-container-registry-unauth.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-unauthenticated-enum-and-initial-entry/az-container-registry-unauth.md` | (page) |  | STRUCTURAL | page reviewed: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-container-registry-unauth.md#az---container-registry-unauth` | Az - Container Registry Unauth |  | STRUCTURAL | title/reference/intro heading |
| `az-unauthenticated-enum-and-initial-entry/az-container-registry-unauth.md#container-registry` | Container Registry |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-container-registry-unauth.md#publicly-shared-data` | Publicly shared data |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-container-registry-unauth.md#anonymous-pull-access` | Anonymous Pull Access |  | SUBSECTION | of #publicly-shared-data: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-container-registry-unauth.md#anonymous-pull-and-known-repository-enumeration-oci-registry-v2-api` | Anonymous pull and known-repository enumeration (OCI Registry v2 API) |  | SUBSECTION | of #publicly-shared-data: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-container-registry-unauth.md#potential-credential-leaks` | Potential credential leaks |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-container-registry-unauth.md#registry-usernamepassword-or-tokens` | Registry username/password or tokens |  | SUBSECTION | of #potential-credential-leaks: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-container-registry-unauth.md#docker-registry-auth-configuration` | Docker registry auth configuration |  | SUBSECTION | of #potential-credential-leaks: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-container-registry-unauth.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-unauthenticated-enum-and-initial-entry/az-cosmosdb-unauth.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-unauthenticated-enum-and-initial-entry/az-cosmosdb-unauth.md` | (page) |  | STRUCTURAL | page reviewed: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-cosmosdb-unauth.md#az---cosmos-db-unauthenticated-enumeration` | Az - Cosmos DB Unauthenticated Enumeration |  | STRUCTURAL | title/reference/intro heading |
| `az-unauthenticated-enum-and-initial-entry/az-cosmosdb-unauth.md#cosmos-db` | Cosmos DB |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-cosmosdb-unauth.md#resource-bruteforce-or-takeover` | Resource bruteforce or takeover |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-cosmosdb-unauth.md#discover-candidate-account-endpoints-through-dns` | Discover candidate account endpoints through DNS |  | SUBSECTION | of #resource-bruteforce-or-takeover: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-cosmosdb-unauth.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-unauthenticated-enum-and-initial-entry/az-device-code-authentication-phishing.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-unauthenticated-enum-and-initial-entry/az-device-code-authentication-phishing.md` | (page) |  | STRUCTURAL | page reviewed: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-device-code-authentication-phishing.md#az---device-code-authentication-phishing` | Az - Device Code Authentication Phishing |  | STRUCTURAL | title/reference/intro heading |
| `az-unauthenticated-enum-and-initial-entry/az-device-code-authentication-phishing.md#entra-id` | Entra ID |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-device-code-authentication-phishing.md#potential-credential-leaks` | Potential credential leaks |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-device-code-authentication-phishing.md#oauth-authorization-response-codes` | OAuth authorization-response codes |  | SUBSECTION | of #potential-credential-leaks: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-device-code-authentication-phishing.md#basic-information` | Basic Information |  | STRUCTURAL | title/reference/intro heading |
| `az-unauthenticated-enum-and-initial-entry/az-device-code-authentication-phishing.md#attack-flow` | Attack Flow |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-device-code-authentication-phishing.md#captive-portal-and-staged-lure-delivery` | Captive-portal and staged-lure delivery |  | SUBSECTION | of #attack-flow: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-device-code-authentication-phishing.md#device-code-request` | Device code request |  | SUBSECTION | of #attack-flow: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-device-code-authentication-phishing.md#poll-the-token-endpoint` | Poll the token endpoint |  | SUBSECTION | of #attack-flow: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-device-code-authentication-phishing.md#common-high-value-first-party-clients` | Common high-value first-party clients |  | SUBSECTION | of #attack-flow: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-device-code-authentication-phishing.md#authorization-code-handoff-phishing` | Authorization-Code Handoff Phishing |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-device-code-authentication-phishing.md#target-selective-lure-wrappers` | Target-selective lure wrappers |  | SUBSECTION | of #authorization-code-handoff-phishing: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-device-code-authentication-phishing.md#token-abuse` | Token Abuse |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-device-code-authentication-phishing.md#offensive-tooling` | Offensive Tooling |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-device-code-authentication-phishing.md#detection--hunting` | Detection & Hunting |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-device-code-authentication-phishing.md#baseline-device-code-sign-ins` | Baseline device-code sign-ins |  | SUBSECTION | of #detection--hunting: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-device-code-authentication-phishing.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-unauthenticated-enum-and-initial-entry/az-devops-unauth.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-unauthenticated-enum-and-initial-entry/az-devops-unauth.md` | (page) |  | STRUCTURAL | page reviewed: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-devops-unauth.md#az---azure-devops-unauth` | Az - Azure DevOps Unauth |  | STRUCTURAL | title/reference/intro heading |
| `az-unauthenticated-enum-and-initial-entry/az-devops-unauth.md#azure-devops` | Azure DevOps |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-devops-unauth.md#public-reconnaissance` | Public reconnaissance |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-devops-unauth.md#organization-existence-enumeration--orgtenant-mapping` | Organization existence enumeration & org→tenant mapping |  | SUBSECTION | of #public-reconnaissance: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-devops-unauth.md#publicly-shared-data` | Publicly shared data |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-devops-unauth.md#anonymous-read-of-public-projects-code-work-items-pipelines-artifacts` | Anonymous read of public projects (code, work items, pipelines, artifacts) |  | SUBSECTION | of #publicly-shared-data: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-devops-unauth.md#secrets-in-public-repos-pipeline-yaml-logs--artifacts` | Secrets in public repos, pipeline YAML, logs & artifacts |  | SUBSECTION | of #publicly-shared-data: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-devops-unauth.md#potential-credential-leaks` | Potential credential leaks |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-devops-unauth.md#azure-devops-pats` | Azure DevOps PATs |  | SUBSECTION | of #potential-credential-leaks: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-devops-unauth.md#legacycontextual-pat-assignments` | Legacy/contextual PAT assignments |  | SUBSECTION | of #potential-credential-leaks: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-devops-unauth.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-unauthenticated-enum-and-initial-entry/az-event-grid-messaging-unauth.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-unauthenticated-enum-and-initial-entry/az-event-grid-messaging-unauth.md` | (page) |  | STRUCTURAL | page reviewed: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-event-grid-messaging-unauth.md#az---event-grid--messaging-unauth` | Az - Event Grid & Messaging Unauth |  | STRUCTURAL | title/reference/intro heading |
| `az-unauthenticated-enum-and-initial-entry/az-event-grid-messaging-unauth.md#event-grid--messaging` | Event Grid & Messaging |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-event-grid-messaging-unauth.md#anonymous-invocation-and-modification` | Anonymous invocation and modification |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-event-grid-messaging-unauth.md#azure-relay-hybrid-connections--anonymous-sender-tunnel` | Azure Relay Hybrid Connections — anonymous sender tunnel |  | SUBSECTION | of #anonymous-invocation-and-modification: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-event-grid-messaging-unauth.md#potential-credential-leaks` | Potential credential leaks |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-event-grid-messaging-unauth.md#service-api-keys` | Service API keys |  | SUBSECTION | of #potential-credential-leaks: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-event-grid-messaging-unauth.md#shared-key-connection-strings` | Shared-key connection strings |  | SUBSECTION | of #potential-credential-leaks: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-event-grid-messaging-unauth.md#azure-sas-urlstokens` | Azure SAS URLs/tokens |  | SUBSECTION | of #potential-credential-leaks: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-event-grid-messaging-unauth.md#resource-bruteforce-or-takeover` | Resource bruteforce or takeover |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-event-grid-messaging-unauth.md#event-grid-topic--namespace-name-enumeration-dns--401404-oracle` | Event Grid topic / namespace name enumeration (DNS + 401/404 oracle) |  | SUBSECTION | of #resource-bruteforce-or-takeover: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-event-grid-messaging-unauth.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-unauthenticated-enum-and-initial-entry/az-front-door-cdn-unauth.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-unauthenticated-enum-and-initial-entry/az-front-door-cdn-unauth.md` | (page) |  | STRUCTURAL | page reviewed: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-front-door-cdn-unauth.md#az---front-door--cdn-origin-exposure--waf-bypass-unauth` | Az - Front Door / CDN Origin Exposure & WAF Bypass Unauth |  | STRUCTURAL | title/reference/intro heading |
| `az-unauthenticated-enum-and-initial-entry/az-front-door-cdn-unauth.md#front-door--cdn` | Front Door / CDN |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-front-door-cdn-unauth.md#authentication-and-access-control-bypass` | Authentication and access-control bypass |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-front-door-cdn-unauth.md#x-azure-fdid-not-validated-service-tag-only-origins` | `X-Azure-FDID` not validated (service-tag-only origins) |  | SUBSECTION | of #authentication-and-access-control-bypass: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-front-door-cdn-unauth.md#afd-waf-remoteaddr-ip-allowlist-bypass-via-x-forwarded-for` | AFD WAF `RemoteAddr` IP-allowlist bypass via `X-Forwarded-For` |  | SUBSECTION | of #authentication-and-access-control-bypass: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-front-door-cdn-unauth.md#direct-to-origin-connection-full-waf--rate-limit--auth-bypass` | Direct-to-origin connection (full WAF / rate-limit / auth bypass) |  | SUBSECTION | of #authentication-and-access-control-bypass: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-front-door-cdn-unauth.md#resource-bruteforce-or-takeover` | Resource bruteforce or takeover |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-front-door-cdn-unauth.md#classic-front-door-and-cdn-endpoint-names` | Classic Front Door and CDN endpoint names |  | SUBSECTION | of #resource-bruteforce-or-takeover: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-front-door-cdn-unauth.md#generated-endpoint-discovery` | Generated endpoint discovery |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-front-door-cdn-unauth.md#publicly-shared-data` | Publicly shared data |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-front-door-cdn-unauth.md#public-edge-response-metadata` | Public edge response metadata |  | SUBSECTION | of #publicly-shared-data: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-front-door-cdn-unauth.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-unauthenticated-enum-and-initial-entry/az-front-door-unauth.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-unauthenticated-enum-and-initial-entry/az-front-door-unauth.md` | (page) |  | STRUCTURAL | page reviewed: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-front-door-unauth.md#az---front-door-unauthenticated-access` | Az - Front Door Unauthenticated Access |  | STRUCTURAL | title/reference/intro heading |
| `az-unauthenticated-enum-and-initial-entry/az-front-door-unauth.md#front-door` | Front Door |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-front-door-unauth.md#authentication-and-access-control-bypass` | Authentication and access-control bypass |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-front-door-unauth.md#remoteaddr-bypass` | RemoteAddr Bypass |  | SUBSECTION | of #authentication-and-access-control-bypass: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-front-door-unauth.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-unauthenticated-enum-and-initial-entry/az-iot-hub-dps-unauth.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-unauthenticated-enum-and-initial-entry/az-iot-hub-dps-unauth.md` | (page) |  | STRUCTURAL | page reviewed: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-iot-hub-dps-unauth.md#az---iot-hub--device-provisioning-service-dps-unauth` | Az - IoT Hub / Device Provisioning Service (DPS) Unauth |  | STRUCTURAL | title/reference/intro heading |
| `az-unauthenticated-enum-and-initial-entry/az-iot-hub-dps-unauth.md#iot-hub--device-provisioning-service-dps` | IoT Hub / Device Provisioning Service (DPS) |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-iot-hub-dps-unauth.md#authentication-prerequisites` | Authentication prerequisites |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-iot-hub-dps-unauth.md#potential-credential-leaks` | Potential credential leaks |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-iot-hub-dps-unauth.md#shared-key-connection-strings` | Shared-key connection strings |  | SUBSECTION | of #potential-credential-leaks: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-iot-hub-dps-unauth.md#enrollment-group-keys-and-device-certificates` | Enrollment-group keys and device certificates |  | SUBSECTION | of #potential-credential-leaks: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-iot-hub-dps-unauth.md#private-key-material` | Private-key material |  | SUBSECTION | of #potential-credential-leaks: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-iot-hub-dps-unauth.md#resource-bruteforce-or-takeover` | Resource bruteforce or takeover |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-iot-hub-dps-unauth.md#existence--mapping-recon` | Existence / mapping recon |  | SUBSECTION | of #resource-bruteforce-or-takeover: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-iot-hub-dps-unauth.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-unauthenticated-enum-and-initial-entry/az-keyvault-unauth.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-unauthenticated-enum-and-initial-entry/az-keyvault-unauth.md` | (page) |  | STRUCTURAL | page reviewed: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-keyvault-unauth.md#az---key-vault-unauth` | Az - Key Vault Unauth |  | STRUCTURAL | title/reference/intro heading |
| `az-unauthenticated-enum-and-initial-entry/az-keyvault-unauth.md#key-vault` | Key Vault |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-keyvault-unauth.md#public-reconnaissance` | Public reconnaissance |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-keyvault-unauth.md#reachability--401403-response-oracle-tenant-id-disclosure` | Reachability + `401`/`403` response oracle (tenant-ID disclosure) |  | SUBSECTION | of #public-reconnaissance: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-keyvault-unauth.md#potential-credential-leaks` | Potential credential leaks |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-keyvault-unauth.md#entra-application-secrets-or-identity-tokens` | Entra application secrets or identity tokens |  | SUBSECTION | of #potential-credential-leaks: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-keyvault-unauth.md#bearer-identity-tokens` | Bearer identity tokens |  | SUBSECTION | of #potential-credential-leaks: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-keyvault-unauth.md#resource-bruteforce-or-takeover` | Resource bruteforce or takeover |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-keyvault-unauth.md#vault-name-existence-oracle-via-dns` | Vault-name existence oracle via DNS |  | SUBSECTION | of #resource-bruteforce-or-takeover: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-keyvault-unauth.md#harvesting-vault-uris-from-public-artifacts` | Harvesting vault URIs from public artifacts |  | SUBSECTION | of #resource-bruteforce-or-takeover: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-keyvault-unauth.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-unauthenticated-enum-and-initial-entry/az-logic-apps-unauth.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-unauthenticated-enum-and-initial-entry/az-logic-apps-unauth.md` | (page) |  | STRUCTURAL | page reviewed: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-logic-apps-unauth.md#az---logic-apps-unauth` | Az - Logic Apps Unauth |  | STRUCTURAL | title/reference/intro heading |
| `az-unauthenticated-enum-and-initial-entry/az-logic-apps-unauth.md#logic-apps` | Logic Apps |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-logic-apps-unauth.md#potential-credential-leaks` | Potential credential leaks |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-logic-apps-unauth.md#logic-apps-signed-callback-urls` | Logic Apps signed callback URLs |  | SUBSECTION | of #potential-credential-leaks: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-logic-apps-unauth.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-unauthenticated-enum-and-initial-entry/az-monitor-alert-phishing.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-unauthenticated-enum-and-initial-entry/az-monitor-alert-phishing.md` | (page) |  | STRUCTURAL | page reviewed: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-monitor-alert-phishing.md#az---monitor-alert-phishing` | Az - Monitor Alert Phishing |  | STRUCTURAL | title/reference/intro heading |
| `az-unauthenticated-enum-and-initial-entry/az-monitor-alert-phishing.md#azure-monitor` | Azure Monitor |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-monitor-alert-phishing.md#setup` | Setup |  | SUBSECTION | of #azure-monitor: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-monitor-alert-phishing.md#entra-id` | Entra ID |  | SUBSECTION | of #azure-monitor: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-monitor-alert-phishing.md#azure-monitor-action-group` | Azure Monitor Action Group |  | SUBSECTION | of #azure-monitor: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-monitor-alert-phishing.md#azure-monitor-alert-rule` | Azure Monitor Alert Rule |  | SUBSECTION | of #azure-monitor: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-monitor-alert-phishing.md#execution` | Execution |  | SUBSECTION | of #azure-monitor: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-monitor-alert-phishing.md#opsec-considerations` | OPSEC Considerations |  | SUBSECTION | of #azure-monitor: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-monitor-alert-phishing.md#public-reconnaissance` | Public reconnaissance |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-monitor-alert-phishing.md#subscription-to-tenant-disclosure` | Subscription-to-tenant disclosure |  | SUBSECTION | of #public-reconnaissance: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-monitor-alert-phishing.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-unauthenticated-enum-and-initial-entry/az-oauth-apps-phishing.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-unauthenticated-enum-and-initial-entry/az-oauth-apps-phishing.md` | (page) |  | STRUCTURAL | page reviewed: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-oauth-apps-phishing.md#az---oauth-apps-phishing` | Az - OAuth Apps Phishing |  | STRUCTURAL | title/reference/intro heading |
| `az-unauthenticated-enum-and-initial-entry/az-oauth-apps-phishing.md#entra-id` | Entra ID |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-oauth-apps-phishing.md#potential-credential-leaks` | Potential credential leaks |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-oauth-apps-phishing.md#oauth-authorization-response-codes` | OAuth authorization-response codes |  | SUBSECTION | of #potential-credential-leaks: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-oauth-apps-phishing.md#oauth-app-phishing` | OAuth App Phishing |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-oauth-apps-phishing.md#app-consent-permissions` | App consent permissions |  | EXCLUDED | NEEDS SCHEMA: app-role consent can grant a named service principal additional API permissions, including non-Graph app roles; require exact source application, app role, target API, successful grant, and effective before/after authority. Credential-injection edges are separately modelled. |
| `az-unauthenticated-enum-and-initial-entry/az-oauth-apps-phishing.md#2-types-of-attacks` | 2 Types of attacks |  | EXCLUDED | Initial access via user consent; no in-tenant permission edge. |
| `az-unauthenticated-enum-and-initial-entry/az-oauth-apps-phishing.md#users-are-allowed-to-consent` | Users are allowed to consent |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-oauth-apps-phishing.md#application-admins` | **Application Admins** |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-oauth-apps-phishing.md#attack-flow-overview` | **Attack Flow Overview** |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-oauth-apps-phishing.md#trusted-first-party-authorization-code-phishing` | Trusted first-party authorization-code phishing |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-oauth-apps-phishing.md#redirect-and-state-interpretation` | Redirect and state interpretation |  | SUBSECTION | of #trusted-first-party-authorization-code-phishing: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-oauth-apps-phishing.md#device-registration-consequences` | Device-registration consequences |  | SUBSECTION | of #trusted-first-party-authorization-code-phishing: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-oauth-apps-phishing.md#detection-and-hunting` | Detection and hunting |  | SUBSECTION | of #trusted-first-party-authorization-code-phishing: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-oauth-apps-phishing.md#example-attack` | Example Attack |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-oauth-apps-phishing.md#other-tools` | Other Tools |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-oauth-apps-phishing.md#post-exploitation` | Post-Exploitation |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-oauth-apps-phishing.md#phishing-post-exploitation` | Phishing Post-Exploitation |  | SUBSECTION | of #post-exploitation: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-oauth-apps-phishing.md#entra-id-applications-admin` | Entra ID Applications Admin |  | EXCLUDED | Same as above - phishing/consent dependent, no deterministic principal edge. |
| `az-unauthenticated-enum-and-initial-entry/az-oauth-apps-phishing.md#application-post-exploitation` | Application Post Exploitation |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-oauth-apps-phishing.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-unauthenticated-enum-and-initial-entry/az-password-spraying.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-unauthenticated-enum-and-initial-entry/az-password-spraying.md` | (page) |  | STRUCTURAL | page reviewed: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-password-spraying.md#az---password-spraying` | Az - Password Spraying |  | STRUCTURAL | title/reference/intro heading |
| `az-unauthenticated-enum-and-initial-entry/az-password-spraying.md#entra-id` | Entra ID |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-password-spraying.md#password-spray` | Password Spray |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-password-spraying.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-unauthenticated-enum-and-initial-entry/az-power-pages-unauth.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-unauthenticated-enum-and-initial-entry/az-power-pages-unauth.md` | (page) |  | STRUCTURAL | page reviewed: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-power-pages-unauth.md#az---power-pages--power-apps-portals-unauth` | Az - Power Pages / Power Apps Portals Unauth |  | STRUCTURAL | title/reference/intro heading |
| `az-unauthenticated-enum-and-initial-entry/az-power-pages-unauth.md#power-pages--power-apps-portals` | Power Pages / Power Apps Portals |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-power-pages-unauth.md#publicly-shared-data` | Publicly shared data |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-power-pages-unauth.md#read-dataverse-records-anonymously-via-the-portal-web-api` | Read Dataverse records anonymously via the portal Web API |  | SUBSECTION | of #publicly-shared-data: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-power-pages-unauth.md#enumerate-exposed-tables--columns` | Enumerate exposed tables & columns |  | SUBSECTION | of #publicly-shared-data: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-power-pages-unauth.md#self-registration-and-guest-access` | Self-registration and guest access |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-power-pages-unauth.md#escalate-anonymous--authenticated-via-open-registration` | Escalate anonymous → "authenticated" via open registration |  | SUBSECTION | of #self-registration-and-guest-access: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-power-pages-unauth.md#resource-bruteforce-or-takeover` | Resource bruteforce or takeover |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-power-pages-unauth.md#discover--fingerprint-power-pages-sites` | Discover & fingerprint Power Pages sites |  | SUBSECTION | of #resource-bruteforce-or-takeover: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-power-pages-unauth.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-unauthenticated-enum-and-initial-entry/az-servicebus-unauth.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-unauthenticated-enum-and-initial-entry/az-servicebus-unauth.md` | (page) |  | STRUCTURAL | page reviewed: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-servicebus-unauth.md#az---service-bus-initial-entry-with-leaked-credentials` | Az - Service Bus Initial Entry with Leaked Credentials |  | STRUCTURAL | title/reference/intro heading |
| `az-unauthenticated-enum-and-initial-entry/az-servicebus-unauth.md#service-bus` | Service Bus |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-servicebus-unauth.md#potential-credential-leaks` | Potential credential leaks |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-servicebus-unauth.md#shared-key-connection-strings` | Shared-key connection strings |  | SUBSECTION | of #potential-credential-leaks: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-servicebus-unauth.md#azure-sas-urlstokens` | Azure SAS URLs/tokens |  | SUBSECTION | of #potential-credential-leaks: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-servicebus-unauth.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-unauthenticated-enum-and-initial-entry/az-sql-unauth.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-unauthenticated-enum-and-initial-entry/az-sql-unauth.md` | (page) |  | STRUCTURAL | page reviewed: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-sql-unauth.md#az---sql-unauthenticated-enumeration--initial-entry` | Az - SQL Unauthenticated Enumeration & Initial Entry |  | STRUCTURAL | title/reference/intro heading |
| `az-unauthenticated-enum-and-initial-entry/az-sql-unauth.md#sql` | SQL |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-sql-unauth.md#potential-credential-leaks` | Potential credential leaks |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-sql-unauth.md#sql-connection-credentials` | SQL connection credentials |  | SUBSECTION | of #potential-credential-leaks: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-sql-unauth.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-unauthenticated-enum-and-initial-entry/az-storage-unauth.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-unauthenticated-enum-and-initial-entry/az-storage-unauth.md` | (page) |  | STRUCTURAL | page reviewed: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-storage-unauth.md#az---storage-unauth` | Az - Storage Unauth |  | STRUCTURAL | title/reference/intro heading |
| `az-unauthenticated-enum-and-initial-entry/az-storage-unauth.md#storage` | Storage |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-storage-unauth.md#publicly-shared-data` | Publicly shared data |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-storage-unauth.md#anonymous-blob-reads-and-listings` | Anonymous blob reads and listings |  | SUBSECTION | of #publicly-shared-data: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-storage-unauth.md#potential-credential-leaks` | Potential credential leaks |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-storage-unauth.md#azure-sas-urlstokens` | Azure SAS URLs/tokens |  | SUBSECTION | of #potential-credential-leaks: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-storage-unauth.md#storage-account-keys` | Storage account keys |  | SUBSECTION | of #potential-credential-leaks: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-storage-unauth.md#resource-bruteforce-or-takeover` | Resource bruteforce or takeover |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-storage-unauth.md#open-storage` | Open Storage |  | SUBSECTION | of #resource-bruteforce-or-takeover: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-storage-unauth.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-unauthenticated-enum-and-initial-entry/az-subdomain-takeover-unauth.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-unauthenticated-enum-and-initial-entry/az-subdomain-takeover-unauth.md` | (page) |  | STRUCTURAL | page reviewed: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-subdomain-takeover-unauth.md#az---subdomain-takeover-dangling-dns-unauth` | Az - Subdomain Takeover (Dangling DNS) Unauth |  | STRUCTURAL | title/reference/intro heading |
| `az-unauthenticated-enum-and-initial-entry/az-subdomain-takeover-unauth.md#app-service-static-web-apps-and-front-door` | App Service, Static Web Apps and Front Door |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-subdomain-takeover-unauth.md#subdomain-takeover-context` | Subdomain takeover context |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-subdomain-takeover-unauth.md#resource-bruteforce-or-takeover` | Resource bruteforce or takeover |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-subdomain-takeover-unauth.md#the-dangling-cname-lifecycle` | The dangling-CNAME lifecycle |  | SUBSECTION | of #resource-bruteforce-or-takeover: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-subdomain-takeover-unauth.md#reliably-takeoverable-suffixes` | Reliably takeoverable suffixes |  | SUBSECTION | of #resource-bruteforce-or-takeover: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-subdomain-takeover-unauth.md#case-dependent--mostly-mitigated-suffixes` | Case-dependent / mostly-mitigated suffixes |  | SUBSECTION | of #resource-bruteforce-or-takeover: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-subdomain-takeover-unauth.md#impact` | Impact |  | SUBSECTION | of #resource-bruteforce-or-takeover: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-subdomain-takeover-unauth.md#enumeration--fingerprinting-fully-unauth` | Enumeration & fingerprinting (fully unauth) |  | SUBSECTION | of #resource-bruteforce-or-takeover: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-subdomain-takeover-unauth.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## az-unauthenticated-enum-and-initial-entry/az-vms-unauth.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-unauthenticated-enum-and-initial-entry/az-vms-unauth.md` | (page) |  | STRUCTURAL | page reviewed: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-vms-unauth.md#az---vms-unauth` | Az - VMs Unauth |  | STRUCTURAL | title/reference/intro heading |
| `az-unauthenticated-enum-and-initial-entry/az-vms-unauth.md#virtual-machines` | Virtual Machines |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-vms-unauth.md#publicly-shared-data` | Publicly shared data |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-vms-unauth.md#public-gallery-images` | Public Gallery Images |  | SUBSECTION | of #publicly-shared-data: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-vms-unauth.md#public-extensions` | Public Extensions |  | SUBSECTION | of #publicly-shared-data: EXCLUDED: unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-vms-unauth.md#ssrf-to-imds-token-theft` | SSRF to IMDS token theft |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-vms-unauth.md#exposed-vulnerable-service` | Exposed vulnerable service |  | EXCLUDED | unauthenticated recon / initial access: no authenticated source principal |
| `az-unauthenticated-enum-and-initial-entry/az-vms-unauth.md#references` | References |  | STRUCTURAL | title/reference/intro heading |

## permission-risk-categorizations.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `permission-risk-categorizations.md` | (page) |  | STRUCTURAL | page reviewed: explanatory / tooling / enumeration |
| `permission-risk-categorizations.md#azure-permissions-categories` | Azure permissions categories |  | STRUCTURAL | title/reference/intro heading |
| `permission-risk-categorizations.md#canonical-yaml` | Canonical YAML |  | EXCLUDED | explanatory / tooling / enumeration |


## Catalog mappings added for master 171e422

## az-persistence/az-dev-center-persistence.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-persistence/az-dev-center-persistence.md#dev-center` | Dev Center |  | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-dev-center-privesc.md#dev-center-environment-identity-deployment` |

## NEEDS SCHEMA

Round 2 originally implemented the proposals below. The later exact-target audit excluded the AVD launching-user and Intune device-user edges because application-group assignment or device association cannot establish a launched session and usable user credential. Custom security attributes in dynamic membership rules also remain excluded. The proposals are kept for traceability; current row statuses above govern the catalog.

<!-- from needs_schema_compute.md -->
# NEEDS_SCHEMA — compute group (G2), HackTricks Cloud rev 171e422

## azure-imagebuilder-template-create-secondary-identity

Ledger: `az-privilege-escalation/az-image-builder-privesc.md#customizer-rce--build-identity-token-theft-marquee` (status NEEDS_SCHEMA; the existing-template path also remains excluded pending an exact build-VM identity join).

Gap: with a net-new image template, the source assigns a template identity T (needs `userAssignedIdentities/assign/action` on T). The build VM gets build-VM identity X only when **T** (not the source) holds `Microsoft.ManagedIdentity/userAssignedIdentities/assign/action` on X (`vmProfile.userAssignedIdentities`). Schema v1 can only express requirements held by the source.

Proposed requirement kind `secondary_principal_action` (azure only):

```yaml
requires:
  all_of:
    - action: Microsoft.VirtualMachineImages/imageTemplates/write
      scope: '*'
    - action: Microsoft.VirtualMachineImages/imageTemplates/run/action
      scope: '*'
    - action: Microsoft.ManagedIdentity/userAssignedIdentities/assign/action
      scope: '{secondary.id}'
    - secondary_principal_action:
        principal: '{secondary.id}'        # a UAMI the source can assign (azure_identity_assignable_in_scope)
        action: Microsoft.ManagedIdentity/userAssignedIdentities/assign/action
        scope: '{target.id}'
target:
  kind: azure_managed_identity
  selector:
    managed_identity_type: user_assigned
  scope: inherited_scope
  aggregate_as: "UAMIs assignable by an Image Builder template identity the source can assign"
confidence: conditional
```

Facts needed: the effective RBAC of each candidate UAMI (already collected as principals) and a new `{secondary.*}` placeholder bound by the evaluator to a principal that satisfies a source-held requirement. Description: "A requirement that must be held by a second principal the source can act as (e.g. an identity it can assign to a resource that then performs the action)."

IMPLEMENTED (shape changed): no generic `secondary_principal_action`; selector `azure_assignable_via_identity_holding: <action>` (kind `azure_managed_identity`) keeps target identities assignable by an intermediate identity the source can itself assign; edges carry condition `via_intermediate_identity:<name>`. Facts already collected. Write:
`requires: {all_of: [{action: Microsoft.VirtualMachineImages/imageTemplates/write}, {action: Microsoft.VirtualMachineImages/imageTemplates/run/action}, {action: Microsoft.ManagedIdentity/userAssignedIdentities/assign/action}]}`, `target: {kind: azure_managed_identity, scope: any, selector: {managed_identity_type: user_assigned, azure_assignable_via_identity_holding: Microsoft.ManagedIdentity/userAssignedIdentities/assign/action}}`.


## Optional: AVD application-group assigned users as targets

`azure-avd-application-write-session-host-rce` targets only session-host managed identities. The launching users' session context is also reached. Proposed selector for `azure_user`:

```yaml
selector:
  azure_users_assigned_to_pivot: true   # users/groups with Desktop Virtualization User on application group {pivot}
```

Facts needed: role assignments of Desktop Virtualization User on application groups (already in RBAC collection; needs group expansion). Not marked NEEDS_SCHEMA in the ledger because the heading is mapped.

IMPLEMENTED: selector `azure_users_assigned_to_pivot: true` (Desktop Virtualization User assignments on the pivot application group, groups expanded; conditional `user_launches_app`). Facts already collected. Write:
`pivot_resource_type: Microsoft.DesktopVirtualization/applicationGroups`, `requires: {all_of: [{action: Microsoft.DesktopVirtualization/applicationgroups/applications/write, scope: '{pivot}'}]}`, `target: {kind: azure_user, scope: tenant, outcome: credentials, selector: {azure_users_assigned_to_pivot: true}}`. Related gap fixed: `azure_host_linked_to_pivot: avd_session_host` is now evaluated (app group -> hostPoolArmPath -> session host resourceId -> VM identity); NEEDS COLLECTOR FACT `avd_session_host` {id, properties.resourceId} per host pool (until then unknown).


## Note (no schema change): AKS node identity

`az-post-exploitation/az-kubernetes-post-exploitation.md#node--kubelet-managed-identity-theft-via-imds--cluster--azure-pivot` is excluded because the cluster -> node cloud identity pivot is already modelled by `catalog/k8s/cloud_pivot.yaml` (`k8s-cloud-node-cloud-identity`). Chaining azure `k8s_cluster_admin` targets into that k8s entry is an evaluator concern.

<!-- from needs_schema_control.md -->
# NEEDS_SCHEMA — group control (HackTricks Cloud 171e422)

## Proposal 1: selector `azure_consumer_of_pivot`

Several pages describe the same escalation. The source writes data that a privileged workload later reads as a credential, endpoint, package, script or command. The workload then acts with its own managed identity. Current selectors cannot say "identities of the workloads that consume this resource":
- `attached_to_service` means the identity of the resource itself.
- `azure_host_linked_to_pivot` means the host that runs jobs for the pivot.
- `credential_stored_in_scope` means secrets held in the pivot.

These techniques stay in the exclusion files until the selector exists.

### schema.py — TARGET_SELECTORS addition (Azure RBAC block)

```python
    "azure_consumer_of_pivot": (("azure",), "string_or_list",
        "Managed identity of a workload that reads the pivot resource (value = consumer binding kind: "
        "key_vault_reference, storage_content, app_configuration_reference, queue_trigger, service_bus_trigger, "
        "event_subscription). Always conditional: whether the consumer trusts the value enough to execute it "
        "is application logic and is never derivable from RBAC."),
```

### schema.py — FACTS_NEEDED addition

```python
    "azure_consumer_of_pivot": "Azure: workload->resource bindings: App Service/Functions app settings and "
                               "connection strings with @Microsoft.KeyVault(...) / App Configuration references, "
                               "AzureWebJobsStorage / WEBSITE_RUN_FROM_PACKAGE / Functions trigger bindings "
                               "(queue, Service Bus, Event Grid), Data Factory / Synapse linked services, "
                               "Batch/Container Apps secret references, Event Grid subscription destinations "
                               "(never values)",
```

### Evaluator behaviour (azure.py)

- When the bindings are not collected, return `unknown` with coverage reason `not_collected`. This matches `azure_host_linked_to_pivot`.
- When they are collected, return the managed identities (system- and user-assigned) of each workload whose binding of the given kind references the `{pivot}` resource or a child of it.
- Always keep the edge `conditional`.

### Draft entries that would use it

```yaml
- id: azure-keyvault-secret-poisoning-consumer
  provider: azure
  service: key_vault
  title: Poison a Key Vault secret read by a privileged workload
  source: src/pentesting-cloud/azure-security/az-privilege-escalation/az-key-vault-privesc.md#write-only-secret-poisoning
  source_revision: 171e422
  summary: Writing a new version of a secret that a workload reads as a credential, endpoint or command makes that workload act on attacker input with its own identity.
  requires:
    all_of: []
    any_of:
      - - action: Microsoft.KeyVault/vaults/secrets/setSecret/action
          data_action: true
          scope: "{pivot}"
      - - action: Microsoft.KeyVault/vaults/accessPolicies/write
          scope: "{pivot}"
  pivot_resource_type: Microsoft.KeyVault/vaults
  target:
    kind: azure_managed_identity
    selector:
      azure_consumer_of_pivot: key_vault_reference
    scope: any
    aggregate_as: "Workload identities consuming secrets of vault {pivot}"
  conditions:
    - id: consumer_trusts_secret
      description: The consuming workload must use the latest secret version in a way that changes what it executes, targets or authenticates to.
  blockers: []
  confidence: conditional
  severity: high
  mitigation: Separate secret writers from readers, pin secret versions in references, and monitor SecretSet on vaults that back privileged workloads.
  references:
    - https://learn.microsoft.com/en-us/azure/app-service/app-service-key-vault-references
  notes: ""

- id: azure-storage-blob-poisoning-consumer
  provider: azure
  service: storage
  title: Poison blobs consumed by a privileged service
  source: src/pentesting-cloud/azure-security/az-privilege-escalation/az-storage-privesc.md#poison-a-privileged-consumer-with-microsoftstoragestorageaccountsblobservicescontainersblobswrite
  source_revision: 171e422
  summary: Overwriting scripts, packages or configuration blobs that Data Factory, Batch, Stream Analytics or similar services load makes them run attacker content with their managed identity.
  requires:
    all_of: []
    any_of:
      - - action: Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write
          data_action: true
          scope: "{pivot}"
      - - action: Microsoft.Storage/storageAccounts/listKeys/action
          scope: "{pivot}"
  pivot_resource_type: Microsoft.Storage/storageAccounts
  target:
    kind: azure_managed_identity
    selector:
      azure_consumer_of_pivot: storage_content
    scope: any
    aggregate_as: "Workload identities loading content from storage account {pivot}"
  conditions:
    - id: consumer_executes_content
      description: The consumer must load and execute or trust the overwritten blob. The Function App package/content case is already modelled in functions.yaml.
  blockers: []
  confidence: conditional
  severity: high
  mitigation: Keep code and configuration blobs for privileged workloads in dedicated accounts with writer separation, and use immutable or versioned packages.
  references:
    - https://learn.microsoft.com/en-us/azure/storage/blobs/authorize-access-azure-active-directory
  notes: ""

- id: azure-appconfig-keyvalue-poisoning-consumer
  provider: azure
  service: app_configuration
  title: Poison App Configuration key-values read by a privileged application
  source: src/pentesting-cloud/azure-security/az-privilege-escalation/az-app-configuration-privesc.md#microsoftappconfigurationconfigurationstoreskeyvalueswrite
  source_revision: 171e422
  summary: Overwriting a key-value or feature flag that a privileged application, job or pipeline uses as an endpoint, module path or command changes what that consumer does with its identity.
  requires:
    all_of: []
    any_of:
      - - action: Microsoft.AppConfiguration/configurationStores/keyValues/write
          scope: "{pivot}"
      - - action: Microsoft.AppConfiguration/configurationStores/ListKeys/action
          scope: "{pivot}"
      - - action: Microsoft.AppConfiguration/configurationStores/RegenerateKey/action
          scope: "{pivot}"
  pivot_resource_type: Microsoft.AppConfiguration/configurationStores
  target:
    kind: azure_managed_identity
    selector:
      azure_consumer_of_pivot: app_configuration_reference
    scope: any
    aggregate_as: "Workload identities consuming App Configuration store {pivot}"
  conditions:
    - id: consumer_trusts_value
      description: The consumer must use the poisoned value in a way that changes what it executes or targets.
  blockers: []
  confidence: conditional
  severity: medium
  mitigation: Disable local auth, separate configuration writers from readers, and use labels/snapshots that are pinned for production consumers.
  references:
    - https://learn.microsoft.com/en-us/azure/azure-app-configuration/concept-enable-rbac
  notes: ""

- id: azure-queue-message-injection-consumer
  provider: azure
  service: storage
  title: Inject queue messages into a privileged consumer
  source: src/pentesting-cloud/azure-security/az-privilege-escalation/az-queue-privesc.md#conditional-escalation-through-a-downstream-consumer
  source_revision: 171e422
  summary: A consumer that trusts queue message fields as commands, URLs or serialized objects runs attacker input with its managed identity.
  requires:
    all_of: []
    any_of:
      - - action: Microsoft.Storage/storageAccounts/queueServices/queues/messages/add/action
          data_action: true
          scope: "{pivot}"
      - - action: Microsoft.Storage/storageAccounts/listKeys/action
          scope: "{pivot}"
  pivot_resource_type: Microsoft.Storage/storageAccounts
  target:
    kind: azure_managed_identity
    selector:
      azure_consumer_of_pivot: queue_trigger
    scope: any
    aggregate_as: "Workload identities triggered by queues of storage account {pivot}"
  conditions:
    - id: consumer_trusts_message
      description: The page states queue write alone does not guarantee code execution; the consumer must unsafely trust message fields.
  blockers: []
  confidence: conditional
  severity: medium
  mitigation: Validate and authenticate message content in consumers, and separate queue writers from privileged consumers.
  references:
    - https://learn.microsoft.com/en-us/azure/storage/queues/authorize-access-azure-active-directory
  notes: The same selector with service_bus_trigger / event_subscription values would cover the Service Bus, Event Hubs and Event Grid injection headings, which are currently excluded as consumer-dependent.
```

The headings that would move from EXCLUDED to MAPPED once this exists:
- az-key-vault-privesc.md#write-only-secret-poisoning
- az-storage-privesc.md#poison-a-privileged-consumer-with-microsoftstoragestorageaccountsblobservicescontainersblobswrite
- az-app-configuration-privesc.md#microsoftappconfigurationconfigurationstoreskeyvalueswrite
- az-queue-privesc.md#conditional-escalation-through-a-downstream-consumer

<!-- from needs_schema_data.md -->

IMPLEMENTED (schema + evaluator; NEEDS COLLECTOR FACT for precision): `azure_consumer_of_pivot: <binding>` with binding one of (or a list) `key_vault_reference`, `storage_content`, `app_configuration_reference`, `queue_trigger`, `service_bus_trigger`, `event_subscription`. A managed identity holding the matching data-read action on the pivot -> conditional `consumer_binding_not_collected`; anything else -> unknown; `event_subscription` always unknown. Write the four draft entries above as written with `selector: {azure_consumer_of_pivot: <binding>}`. Collector fact: workload binding config (app settings with Key Vault / App Configuration references, function trigger bindings, event subscription destinations).


# NEEDS_SCHEMA — group data (HackTricks Cloud 171e422)

Both items are on `az-privilege-escalation/az-fabric-privesc.md`. Microsoft Fabric authorization lives in the Fabric plane: workspace roles and tenant settings. It is not ARM RBAC. PEASO collects neither the Fabric workspace role assignments nor the binding from a workspace to its identity. The current exclusions in `_excluded_rbac.yaml` stay until the schema and collector changes below exist. In the ledger these headings have status NEEDS_SCHEMA.

## Proposal 1: requirement kind `fabric_workspace_role`

### schema.py

```python
# REQUIREMENT_FIELDS["azure"] gains "fabric_workspace_role", "fabric_workspace"
# AZURE_REQUIREMENT_KINDS gains "fabric_workspace_role"
FABRIC_WORKSPACE_ROLES = ("Admin", "Member", "Contributor", "Viewer")
# Semantics: the source (directly or through an Entra group) holds a Fabric workspace role at least as strong as
# the named one on the workspace `fabric_workspace` ('*' = any workspace; '{target.host_resource}' = the
# workspace that owns the target identity). Not collected -> unknown with coverage reason not_collected.
```

### Collector facts needed

- `GET https://api.fabric.microsoft.com/v1/workspaces` and `GET /v1/workspaces/{id}/roleAssignments`. The read-only Fabric scope is `Workspace.Read.All`.
- The tenant setting "Service principals can use Fabric APIs", from `GET /v1/admin/tenantsettings`. A Fabric admin is required to read it. When it is unreadable, record it as unknown.

## Proposal 2: selector `fabric_workspace_identity`

Fabric target identities are Entra service principals. Today `azure_service_principal` can only be picked by id or name glob, by `credential_stored_in_scope`, or by the generic selectors.

### schema.py — TARGET_SELECTORS addition (Azure RBAC block)

```python
    "fabric_workspace_identity": (("azure",), "bool_true",
        "Target service principal is the workspace identity of a Fabric workspace; the workspace is exposed as "
        "{target.host_resource}. Not collected -> unknown."),
```

### Collector facts needed

- For each workspace, `GET /v1/workspaces/{id}`, field `workspaceIdentity.servicePrincipalId`. Join that id to the inventoried Entra service principal.

### Draft entries that would use them

```yaml
- id: azure-fabric-notebook-workspace-identity
  provider: azure
  service: fabric
  title: Run a Fabric notebook or Spark job definition as the workspace identity
  source: src/pentesting-cloud/azure-security/az-privilege-escalation/az-fabric-privesc.md#notebook--spark-job-rce-as-the-submitting-identity--token--key-vault-theft
  source_revision: 171e422
  summary: A Fabric workspace Contributor can create and schedule notebooks or Spark job definitions; scheduled and API-triggered runs execute as the workspace managed identity, whose Entra tokens are reachable from the code.
  requires:
    all_of:
      - fabric_workspace_role: Contributor
        fabric_workspace: '{target.host_resource}'
  target:
    kind: azure_service_principal
    selector: {fabric_workspace_identity: true}
    scope: any
    aggregate_as: Fabric workspace identities
    outcome: workload_execution
  conditions: [fabric_sp_api_enabled_if_source_is_sp]
  confidence: conditional
  severity: high
  references: [https://learn.microsoft.com/en-us/fabric/security/workspace-identity]

- id: azure-fabric-administrator-workspace-identity
  provider: azure
  service: fabric
  title: Fabric Administrator grants itself a workspace role and runs code as the workspace identity
  source: src/pentesting-cloud/azure-security/az-privilege-escalation/az-fabric-privesc.md#fabric-administrator-entra--tenant-takeover--org-wide-scanner-recon
  source_revision: 171e422
  summary: The Fabric administrator (or Power Platform administrator) Entra role can take over any workspace and then use the notebook path as that workspace's identity.
  requires:
    all_of: []
    any_of:
      - - entra_role: Fabric Administrator
      - - entra_role: Power Platform Administrator
  target:
    kind: azure_service_principal
    selector: {fabric_workspace_identity: true}
    scope: any
    aggregate_as: Fabric workspace identities
    outcome: workload_execution
  confidence: conditional
  severity: high
  references: [https://learn.microsoft.com/en-us/fabric/admin/roles]
```

The condition `fabric_sp_api_enabled_if_source_is_sp` is new. It is true unless the source is a service principal and the "Service principals can use Fabric APIs" tenant setting is off.

Not proposed: the Fabric connection/gateway credential use (`#connection--gateway-credential-confused-deputy-exfil`). It only gives use of a data-source credential and no identity, so it stays EXCLUDED.

<!-- from needs_schema_entra.md -->

IMPLEMENTED (Proposals 1 and 2; NEEDS COLLECTOR FACTS): requirement `fabric_workspace_role: Admin|Member|Contributor|Viewer` (rank comparison, groups included) with optional `fabric_workspace`, and selector `fabric_workspace_identity: true`; `{target.host_resource}` resolves to the identity's workspace. Write the drafts above as written, e.g. `requires: {all_of: [{fabric_workspace_role: Contributor, fabric_workspace: '{target.host_resource}'}]}`, `target: {kind: azure_service_principal, scope: any, outcome: workload_execution, selector: {fabric_workspace_identity: true}}`. Collector facts: `fabric_workspace_role_assignment` {principal.id|principalId, role, workspaceId, id}, `fabric_workspace` {id, workspaceIdentity.servicePrincipalId}. Fabric connection / gateway credentials stay excluded.


# G1 (Entra) — NEEDS_SCHEMA proposals (hacktricks-cloud 171e422)

Each item is a real escalation that schema v1 cannot select precisely. The YAML below is a proposal only: none of these kinds exist yet in `schema.py`/`evaluator.py`, and nothing here has been added to the catalog. Until they exist, the headings stay in `_excluded_entraid.yaml` / `_excluded_171e422_entra.yaml` with a NEEDS_SCHEMA reason.

## NS-intune-managed-device
Headings: `az-intune-privesc.md#cloud---on-prem`, `#fleet-rce-via-platform-scripts-system-over-graph`, `#macos-shell-scripts-as-root--win32-apps-as-system`, `#privesc-chain--intune-administrator--intune-scoped-sp---global-admin`.
Gap: there is no target kind for an Intune-managed device and no facts linking a device to the identities that sign in to it (primary user, recent sign-ins, Entra-joined device identity). Without these, the identity gained can't be selected.
Collector needs: managedDevices (id, OS, userId/primary user, azureADDeviceId), Intune RBAC role assignments and scope tags, and the users signed in per device.
```yaml
id: azure-intune-managed-device-code-execution
provider: azure
requires:
  any_of:
    - - {kind: entra_role, role: Intune Administrator}
    - - {kind: graph_app_permission, permission: DeviceManagementScripts.ReadWrite.All}
    - - {kind: graph_app_permission, permission: DeviceManagementConfiguration.ReadWrite.All}
    - - {kind: graph_app_permission, permission: DeviceManagementApps.ReadWrite.All}
    - - {kind: intune_rbac_permission, permission: Microsoft.Intune_DeviceConfigurations_Assign}   # new kind
target:
  kind: azure_user                          # identity gained = privileged user signed in to the device
  selectors:
    entra_user_signed_in_to_managed_device_in_intune_scope: true   # new selector (scope tags / RBAC scope)
    entra_role_assignable: true
blockers: [intune_multi_admin_approval_required]                    # new blocker (MAA on scripts/apps)
confidence: conditional
```
A second edge (`target.kind: entra_managed_device`) would represent SYSTEM/root on the device itself, if device nodes are added to the graph.

IMPLEMENTED for the signed-in user (NEEDS COLLECTOR FACTS); the device itself as a target kind is REJECTED (SYSTEM/root on an endpoint is not a cloud principal). Requirement `intune_permission: <resourceAction glob>` (member groups; always conditional `intune_scope_tags_not_evaluated`), selector `intune_managed_device_user: true` (conditional `device_session_not_verified`), blocker `intune_multi_admin_approval_required`. Write:
`requires: {any_of: [[{intune_permission: Microsoft.Intune_DeviceConfigurations_Assign}], [{entra_role: Intune Administrator}], [{graph_app_permission: DeviceManagementConfiguration.ReadWrite.All}]]}` (each any_of alternative is a list), `target: {kind: azure_user, scope: tenant, outcome: credentials, selector: {intune_managed_device_user: true}}`, `blockers: [intune_multi_admin_approval_required]`. Collector facts: `intune_role_assignment` {members[], roleDefinition.displayName, roleDefinition.rolePermissions[].resourceActions[].allowedResourceActions[]}, `intune_managed_device` {id, userId}.


## NS-pim-group-eligibility
Heading: `az-pim-privesc.md#pim-for-groups-the-sneaky-path` (partly MAPPED to `azure-entraid-graph-pim-groups-active-assignment`).
Gap: `entra_pim_eligible_role` covers directory roles only. A principal that is *eligible* for membership or ownership of a PIM-onboarded group can activate it with no extra permission.
```yaml
id: azure-entraid-pim-group-eligible-activation
requires:
  all_of:
    - {kind: entra_pim_eligible_group, access_id: [member, owner]}      # new requirement kind
target:
  kind: entra_group
  selectors:
    entra_pim_group_eligible_for_source: true                          # new selector
blockers: [pim_approval_required_by_other_principal]
confidence: high
```

IMPLEMENTED (NEEDS COLLECTOR FACT): selector `entra_pim_group_eligible_for_source: true | member | owner` (eligibilities with status Provisioned; conditional `pim_activation_required`). Write:
`requires: {}`, `source_kind: azure_user`, `target: {kind: entra_group, scope: tenant, selector: {entra_pim_group_eligible_for_source: true}}`, `blockers: [pim_approval_required_by_other_principal]`. Collector fact: `directory_group_eligibility_schedule` {principalId, groupId, accessId, status}.


## NS-governance-catalog-self-grant
Headings: `az-entra-id-governance-privesc.md#catalog-scoped-self-grant-privesc`, `az-persistence/az-entra-id-governance-persistence.md#auto-assignment-policy-abuse-persistence`.
Gap: catalog roles (Catalog owner, Access package manager, Access package assignment manager) and catalog resources are not collected.
```yaml
id: azure-entraid-entitlement-catalog-self-grant
requires:
  any_of:
    - - {kind: entra_entitlement_catalog_role, role: [Catalog owner, Access package manager, Access package assignment manager]}  # new kind
    - - {kind: graph_app_permission, permission: EntitlementManagement.ReadWrite.All}
target:
  kind: [entra_group, azure_service_principal, entra_role]
  selectors:
    entra_resource_in_catalog_managed_by_source: true                   # new selector
blockers: [access_package_approval_by_other_principal]                  # new blocker
confidence: high
```

IMPLEMENTED (NEEDS COLLECTOR FACTS): requirement `entra_catalog_role: <Catalog owner|Access package manager|Access package assignment manager>` with `catalog: '{target.catalog}'` (`appScopeId: "/"` = tenant-wide), selector `entra_resource_in_catalog: true`, blocker `access_package_approval_by_other_principal`. Write:
`requires: {any_of: [[{entra_catalog_role: Catalog owner, catalog: '{target.catalog}'}], [{entra_catalog_role: Access package manager, catalog: '{target.catalog}'}], [{entra_catalog_role: Access package assignment manager, catalog: '{target.catalog}'}]]}`, `target: {kind: entra_group, scope: tenant, selector: {entra_resource_in_catalog: true}}` (or `entra_role` / `azure_service_principal`), `blockers: [access_package_approval_by_other_principal]`. Persistence variant: a second entry with `requires: {all_of: [{graph_app_permission: EntitlementManagement.ReadWrite.All}]}` and the same target. Collector facts: `entitlement_role_assignment` {principalId, roleDefinitionId, roleDefinition.displayName, appScopeId}, `entitlement_catalog_resource` {catalogId, originId}.


## NS-governance-guest-auto-rule
Heading: `az-entra-id-governance-privesc.md#guest-self-enrolment-via-loose-auto-assignment-rule-privesc`.
Gap: automatic-assignment policy rules and their target resources are not collected. This is analogous to `azure-entraid-dynamic-group-guest-invite`.
```yaml
id: azure-entraid-access-package-guest-auto-assignment
requires:
  all_of:
    - {kind: entra_tenant_setting, setting: guest_invite_allowed_for_source}
target:
  kind: [entra_group, azure_service_principal, entra_role]
  selectors:
    entra_access_package_auto_rule_satisfiable_by_invited_guest: true   # new selector
confidence: conditional
```

IMPLEMENTED (NEEDS COLLECTOR FACTS): selector `entra_access_package_auto_assignment_open_to_guest: true` (policy with requestAccessForAllowedTargets, scope not all-members / all-SPs / not-specified, rule not requiring `user.userType -eq "Member"`; conditional `auto_assignment_rule_semantics_approximated`, text heuristic). Write:
`requires: {all_of: [{entra_tenant_setting: guest_invites_allowed_for_source}]}`, `target: {kind: entra_group, scope: tenant, selector: {entra_access_package_auto_assignment_open_to_guest: true}}`. Collector facts: `entitlement_assignment_policy` {accessPackageId, allowedTargetScope, automaticRequestSettings.requestAccessForAllowedTargets, specificAllowedTargets[].membershipRule}, `entitlement_access_package_resource` {accessPackageId, originId}.


## NS-custom-security-attributes
Heading: `az-entraid-privesc/README.md#custom-security-attributes-feeding-abac--dynamic-membership`.
Gap: attribute assignments and the ABAC conditions or dynamic rules that consume them are not collected.
```yaml
id: azure-entraid-custom-security-attribute-condition
requires:
  any_of:
    - - {kind: entra_role, role: Attribute Assignment Administrator}
    - - {kind: graph_app_permission, permission: CustomSecAttributeAssignment.ReadWrite.All}
target:
  kind: [entra_group, azure_role_assignment_condition]
  selectors:
    entra_condition_satisfiable_by_custom_attribute: true               # new selector (attribute set scoped)
confidence: conditional
```

IMPLEMENTED for ABAC role-assignment conditions (facts already collected); the dynamic-membership part is REJECTED (dynamic membership rules do not take custom security attributes per Microsoft documentation; not verified offline). Selector `azure_assignment_condition_uses_principal_attribute: true` (the source's role assignment conditions referencing `@Principal[Microsoft.Directory/CustomSecurityAttributes...`; conditional `attribute_value_satisfying_condition_not_verified`). Write:
`requires: {any_of: [[{entra_role: Attribute Assignment Administrator}], [{graph_app_permission: CustomSecAttributeAssignment.ReadWrite.All}]]}`, `target: {kind: azure_dataplane_admin, scope: any, outcome: permission_grant, selector: {azure_assignment_condition_uses_principal_attribute: true}}` (or kind `azure_scope_owner`).


## NS-aad-dc-administrators
Heading: `az-lateral-movement-cloud-on-prem/az-domain-services.md#pivoting`.
Gap: membership of *AAD DC Administrators* gives administrator rights on VMs joined to Entra Domain Services. Code execution there can reach those VMs' managed identities. Schema v1 has no selector for DS-joined VMs.
```yaml
id: azure-entra-domain-services-dc-admins-vm
requires:
  all_of:
    - {kind: entra_group_member, group: AAD DC Administrators}          # new kind (or reuse group membership facts)
target:
  kind: azure_managed_identity
  selectors:
    attached_to_vm_joined_to_entra_domain_services: true                # new selector
confidence: conditional
```

IMPLEMENTED (facts already collected): requirement `entra_group_member: <group id|name>` (transitive; unknown when that group's membership is not collected) and selector `attached_to_vm_joined_to_entra_domain_services: true` (VM JsonADDomainExtension domain equals a Domain Services domainName -> conditional `domain_join_state_not_verified`; VMs without the extension -> unknown; no Domain Services and every subscription inventoried -> dropped). Write:
`requires: {all_of: [{entra_group_member: AAD DC Administrators}]}`, `target: {kind: azure_managed_identity, scope: any, selector: {attached_to_service: Microsoft.Compute/virtualMachines, attached_to_vm_joined_to_entra_domain_services: true}}`.

## Additive v4 reviewed mappings (HackTricks Cloud 4913b6d88ced9972f72ccdd708d21641725a6fb5)

The first line records the historical 0b3633 heading sweep. Rows below are reviewed catalog additions bound to the v4 manifest; they supersede a historical status only for the exact conditional technique named here.

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-api-management-privesc.md#microsoftapimanagementserviceuserstokenaction` | Exact developer-portal SSO principal | Microsoft.ApiManagement/service/users/token/action | MAPPED | `azure-apim-developer-portal-sso-external-principal` |
| `az-privilege-escalation/az-data-factory-privesc.md#steal-the-factorys-github-oauth-token-with-factoriesgetgithubaccesstokenaction` | Exact GitHub OAuth subject and repository | Microsoft.DataFactory/factories/getGitHubAccessToken/action | MAPPED | `azure-datafactory-github-oauth-external-principal` |
| `az-privilege-escalation/az-event-grid-privesc.md#backdoor-mqtt-client-via-namespacesclients--clientgroups--permissionbindingswrite` | Exact MQTT client grant | Microsoft.EventGrid/namespaces/permissionBindings/write | MAPPED | `azure-eventgrid-mqtt-client-grant-external-principal` |
| `az-privilege-escalation/az-vmware-solution-avs-privesc.md#cloudadmin--nsx-t-credential-disclosure-listadmincredentials` | Exact AVS vCenter and NSX-T credential pivots | Microsoft.AVS/privateClouds/listAdminCredentials/action | MAPPED | `azure-avs-list-vcenter-cloudadmin-external-principal` `azure-avs-list-nsxt-admin-external-principal` |
| `az-privilege-escalation/az-vmware-solution-avs-privesc.md#run-command-rce-without-reading-credentials-scriptexecutionswrite` | Exact AVS Run Command identity grant | Microsoft.AVS/privateClouds/scriptExecutions/write | MAPPED | `azure-avs-run-command-vcenter-grant-external-principal` |
| `az-post-exploitation/az-container-registry-post-exploitation.md#microsoftcontainerregistryregistriespullread` | Extract credentials from ACR image layers | Microsoft.ContainerRegistry/registries/pull/read | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-container-registry-privesc.md#microsoftcontainerregistryregistriespullread` |
| `az-cross-tenant-and-cross-subscription-attacks/historical-cross-tenant-vulnerabilities.md#cross-subscription-not-cross-tenant-abuse-worth-noting` | Pull ACR image with verified principal credential | Microsoft.ContainerRegistry/registries/pull/read | EXCLUDED | Strict principal-boundary audit: This path relies on generic reviewed Status/VerifiedPreconditions/EvidenceRef flags; the evaluator has no typed proof of the specific source capability, action, usable credential or target-identity gain. |
| `az-post-exploitation/az-api-management-post-exploitation.md#microsoftapimanagementservicegatewaysgetconfigurationaction--bulk-policysecret-pull-data-action-bypasses-the-administrative-log` | APIM gateway configuration embedded credentials | Microsoft.ApiManagement/service/gateways/getConfiguration/action | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-api-management-privesc.md#microsoftapimanagementservicegatewaysgetconfigurationaction--bulk-policysecret-pull-data-action-bypasses-the-administrative-log` |
| `az-post-exploitation/az-app-configuration-post-exploitation.md#bulk-exfil--loot-persistence-via-snapshots-configurationstoressnapshotsread--write` | Recover credentials retained in App Configuration snapshot | Microsoft.AppConfiguration/configurationStores/snapshots/read | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-app-configuration-privesc.md#bulk-exfil--loot-persistence-via-snapshots-configurationstoressnapshotsread--write` |
| `az-privilege-escalation/az-spring-apps-privesc.md#custom-container--build-service-supply-chain` | Custom container / build-service supply chain | Microsoft.AppPlatform/Spring/buildServices/builders/buildpackBindings/write, Microsoft.AppPlatform/Spring/buildServices/builders/write | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-spring-apps-privesc.md#app-deploy-rce--managed-identity-theft-marquee` |
| `az-privilege-escalation/az-sre-agent-privesc.md#drive-the-agents-managed-identity--instruction--tool-config-injection-agentsthreads-agentswrite-` | Drive the agent's managed identity — instruction / tool-config injection (agents/threads, agents/write, ...) | Microsoft.App/agents/threads/approve/action | EXCLUDED | NEEDS SCHEMA: exact agent run mode, accepted tool invocation, and newly authorized action by the named identity are uncollected. |
| `az-privilege-escalation/az-sql-privesc.md#elastic-jobs-run-arbitrary-t-sql-through-jobagentsjobsstepswrite--executionswrite` | Elastic Jobs: run arbitrary T-SQL through jobAgents/jobs/steps/write + executions/write | Microsoft.Sql/servers/jobAgents/credentials/read, Microsoft.Sql/servers/jobAgents/jobs/executions/write, Microsoft.Sql/servers/jobAgents/jobs/steps/write, Microsoft.Sql/servers/jobAgents/targetGroups/read | EXCLUDED | Strict principal-boundary audit: This path relies on generic reviewed Status/VerifiedPreconditions/EvidenceRef flags; the evaluator has no typed proof of the specific source capability, action, usable credential or target-identity gain. |
| `az-post-exploitation/az-automation-accounts-post-exploitation.md#harvest-secrets-from-prior-job-output-and-streams` | Read tokens and credentials from prior Automation job output | Microsoft.Automation/automationAccounts/jobs/output/read, Microsoft.Automation/automationAccounts/jobs/read, Microsoft.Automation/automationAccounts/jobs/streams/read | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-automation-accounts-privesc.md#harvest-secrets-from-prior-job-output-and-streams` |
| `az-post-exploitation/az-automation-accounts-post-exploitation.md#read-runbook-source-for-hardcoded-secrets` | Read hardcoded credentials from runbook source | Microsoft.Automation/automationAccounts/runbooks/content/read | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-automation-accounts-privesc.md#read-runbook-source-for-hardcoded-secrets` |
| `az-post-exploitation/az-virtual-desktop-post-exploitation.md#common-techniques` | Overwrite an assigned App Attach image to reach launching users | Microsoft.Storage/storageAccounts/fileServices/fileshares/files/write | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-virtual-desktop-privesc.md#fleet-rce-via-applicationgroupsapplicationswrite-lolbin-commandlinearguments` |
| `az-cross-tenant-and-cross-subscription-attacks/resource-and-service-sharing-attacks.md#resource--service-sharing-matrix` | Read shared gallery image with verified cloud credential | Microsoft.Compute/galleries/images/versions/read | EXCLUDED | Strict principal-boundary audit: This path relies on generic reviewed Status/VerifiedPreconditions/EvidenceRef flags; the evaluator has no typed proof of the specific source capability, action, usable credential or target-identity gain. |
| `az-privilege-escalation/az-managed-applications-privesc.md#deploy-as-identity-inside-a-managed-app` | Deploy an authorized managed-app template that grants a new identity privileged RBAC | Microsoft.Solutions/applicationDefinitions/write, Microsoft.Solutions/applications/write | EXCLUDED | Strict principal-boundary audit: This path relies on generic reviewed Status/VerifiedPreconditions/EvidenceRef flags; the evaluator has no typed proof of the specific source capability, action, usable credential or target-identity gain. |
| `az-privilege-escalation/az-monitor-privesc.md#microsoftinsightswebtestsread` | Read a reusable credential stored in an availability test | Microsoft.Insights/webtests/read | EXCLUDED | NEEDS SCHEMA: Exact credential in the stored request, its subject, usability, and newly permitted action must be verified. |
| `az-privilege-escalation/az-logic-apps-privesc.md#microsoftlogicworkflowsrunsactionsread` | Recover a reusable principal credential from Logic App run output | Microsoft.Logic/workflows/runs/actions/read | EXCLUDED | Strict principal-boundary audit: This path relies on generic reviewed Status/VerifiedPreconditions/EvidenceRef flags; the evaluator has no typed proof of the specific source capability, action, usable credential or target-identity gain. |
| `az-privilege-escalation/az-logic-apps-privesc.md#microsoftlogicworkflowsrunsactionsrequesthistoriesread` | Recover a reusable principal credential from Logic App run output | Microsoft.Logic/workflows/runs/actions/requestHistories/read | EXCLUDED | Strict principal-boundary audit: This path relies on generic reviewed Status/VerifiedPreconditions/EvidenceRef flags; the evaluator has no typed proof of the specific source capability, action, usable credential or target-identity gain. |
| `az-post-exploitation/az-blob-storage-post-exploitation.md#microsoftstoragestorageaccountsblobservicescontainersblobsread` | Read Entra credentials embedded in blobs | Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read | EXCLUDED | Moved to privilege escalation section: `az-privilege-escalation/az-storage-privesc.md#microsoftstoragestorageaccountsblobservicescontainersblobsread` |
| `az-cross-tenant-and-cross-subscription-attacks/historical-cross-tenant-vulnerabilities.md#trusted-ip-and-metadata-abuse` | Verified VM SSRF to managed identity |  | EXCLUDED | Strict principal-boundary audit: This path relies on generic reviewed Status/VerifiedPreconditions/EvidenceRef flags; the evaluator has no typed proof of the specific source capability, action, usable credential or target-identity gain. |
| `az-privilege-escalation/az-servicebus-privesc.md#authorization-rule-key-disclosure-and-rotation` | Authorization-rule key disclosure and rotation | Verified exact-target native evidence | EXCLUDED | Strict principal-boundary audit: Bounded service effect explicitly modeled without a target principal or a grant of permissions to the caller. |
| `az-privilege-escalation/az-spring-apps-privesc.md#listtestkeys--public-test-endpoints` | listTestKeys / public test endpoints | Verified exact-target native evidence | EXCLUDED | Strict principal-boundary audit: Bounded service effect explicitly modeled without a target principal or a grant of permissions to the caller. |
| `az-privilege-escalation/az-spring-apps-privesc.md#microsoftappplatformspringregeneratetestkeyaction` | Microsoft.AppPlatform/Spring/regenerateTestKey/action | Verified exact-target native evidence | EXCLUDED | Strict principal-boundary audit: Bounded service effect explicitly modeled without a target principal or a grant of permissions to the caller. |
| `az-privilege-escalation/az-healthcare-apis-privesc.md#self-grant-fhirdicom-data-roles-privesc` | Grant oneself a FHIR or DICOM data role at the service scope | Microsoft.Authorization/roleAssignments/write | EXCLUDED | NEEDS SCHEMA: verify the exact RBAC condition, target principal, successful self-grant of the FHIR/DICOM data role, and newly authorized data action. |
| `az-privilege-escalation/az-healthcare-apis-privesc.md#az---healthcare-apis-privilege-escalation` | Az - Healthcare APIs Privilege Escalation |  | STRUCTURAL | Page title; service-scope role grant is conditional pending typed self-grant proof. |
| `az-privilege-escalation/az-container-registry-privesc.md#cross-subscription-not-cross-tenant-abuse-worth-noting` | Cross-subscription ACR Tasks example | Microsoft.ContainerRegistry/registries/tasks/write | SUBSECTION | Supporting example of the task execution path mapped at `#microsoftcontainerregistryregistriestaskswrite`; image reads alone do not establish a privilege gain. |
| `az-privilege-escalation/az-virtual-desktop-privesc.md#common-techniques` | Common techniques | Microsoft.DesktopVirtualization/applicationGroups/write | SUBSECTION | The conditional RemoteApp variant is discussed at `#fleet-rce-via-applicationgroupsapplicationswrite-lolbin-commandlinearguments` and remains excluded pending exact launch and credential proof. |
| `az-post-exploitation/az-vms-and-network-post-exploitation.md#trusted-ip-and-metadata-abuse` | Trusted-IP and metadata abuse |  | EXCLUDED | Service-tag bypass and generic IMDS SSRF context do not establish a concrete source permission and bound target managed identity. |
| `az-privilege-escalation/az-purview-privesc.md#microsoftpurviewpolicyelementswrite--purview-access-policies-into-governed-sqlstorage` | Microsoft.Purview/policyElements/write — Purview access policies into governed SQL/Storage | Verified exact-target native evidence | MAPPED | `azure-purview-policy-self-grant` |
| `az-privilege-escalation/az-servicebus-privesc.md#microsoftservicebusnamespacesauthorizationruleswrite` | Microsoft.ServiceBus/namespaces/AuthorizationRules/write | Verified exact-target native evidence | EXCLUDED | Strict principal-boundary audit: Bounded service effect explicitly modeled without a target principal or a grant of permissions to the caller. |
| `az-privilege-escalation/az-servicebus-privesc.md#microsoftservicebusnamespacesdisasterrecoveryconfigsauthorizationruleslistkeysaction` | Microsoft.ServiceBus/namespaces/disasterRecoveryConfigs/authorizationRules/listkeys/action | Verified exact-target native evidence | EXCLUDED | Strict principal-boundary audit: Bounded service effect explicitly modeled without a target principal or a grant of permissions to the caller. |
| `az-privilege-escalation/az-servicebus-privesc.md#microsoftservicebusnamespacesqueuestopicsauthorizationruleslistkeysaction-or-microsoftservicebusnamespacesqueuestopicsauthorizationrulesregeneratekeysaction` | Microsoft.ServiceBus/namespaces/[queues\|topics]/authorizationRules/ListKeys/action OR Microsoft.ServiceBus/namespaces/[queues\|topics]/authorizationRules/regenerateKeys/action | Verified exact-target native evidence | EXCLUDED | Strict principal-boundary audit: Bounded service effect explicitly modeled without a target principal or a grant of permissions to the caller. |
| `az-privilege-escalation/az-storage-privesc.md#microsoftstoragestorageaccountslistaccountsasaction` | Microsoft.Storage/storageAccounts/listAccountSas/action | Verified exact-target native evidence | EXCLUDED | Strict principal-boundary audit: Bounded service effect explicitly modeled without a target principal or a grant of permissions to the caller. |
| `az-privilege-escalation/az-storage-privesc.md#microsoftstoragestorageaccountslistkeysaction` | Microsoft.Storage/storageAccounts/listkeys/action | Verified exact-target native evidence | EXCLUDED | Strict principal-boundary audit: Bounded service effect explicitly modeled without a target principal or a grant of permissions to the caller. |
| `az-privilege-escalation/az-storage-privesc.md#microsoftstoragestorageaccountslistservicesasaction` | Microsoft.Storage/storageAccounts/listServiceSas/action | Verified exact-target native evidence | EXCLUDED | Strict principal-boundary audit: Bounded service effect explicitly modeled without a target principal or a grant of permissions to the caller. |
| `az-privilege-escalation/az-storage-privesc.md#microsoftstoragestorageaccountsregeneratekeyaction` | Microsoft.Storage/storageAccounts/regenerateKey/action | Verified exact-target native evidence | EXCLUDED | Strict principal-boundary audit: Bounded service effect explicitly modeled without a target principal or a grant of permissions to the caller. |
| `az-privilege-escalation/az-static-web-apps-privesc.md#microsoftwebstaticsiteslistsecretsaction` | Microsoft.Web/staticSites/listSecrets/action | Verified exact-target native evidence | EXCLUDED | NEEDS SCHEMA: Exact deployment key subject, usability, and newly permitted deployment action must be verified. |
| `az-privilege-escalation/az-databricks-privesc.md#unity-catalog-storage-credential--external-location-abuse` | Obtain temporary Azure Storage authority through Unity Catalog | Verified exact-target native evidence | EXCLUDED | Strict principal-boundary audit: Bounded service effect explicitly modeled without a target principal or a grant of permissions to the caller. |
| `az-privilege-escalation/az-storage-privesc.md#hns-acl-takeover-and-blob-super-user-data-action` | Rewrite ADLS Gen2 path ACLs for new access | Verified exact-target native evidence | MAPPED | `azure-storage-adls-acl-self-grant` |
| `az-privilege-escalation/az-storage-privesc.md#microsoftstoragestorageaccountsfileservicesfilesharesfilesmodifypermissionsaction` | Rewrite Azure Files NTFS ACLs for new access | Verified exact-target native evidence | MAPPED | `azure-storage-files-acl-self-grant` |

| `az-privilege-escalation/az-storage-privesc.md#microsoftstoragestorageaccountslocaluserswrite-microsoftstoragestorageaccountslocalusersread` | `Microsoft.Storage/storageAccounts/localusers/write (Microsoft.Storage/storageAccounts/localusers/read)` | Microsoft.Storage/storageAccounts/localusers/write;Microsoft.Storage/storageAccounts/localusers/read | MAPPED | `azure-audit-microsoftstoragestorageaccountslocaluserswrite-microsoftstoragestorageac` |

| `az-privilege-escalation/az-storage-privesc.md#microsoftstoragestorageaccountslocalusersregeneratepasswordaction` | `Microsoft.Storage/storageAccounts/localusers/regeneratePassword/action` | Microsoft.Storage/storageAccounts/localusers/regeneratePassword/action | MAPPED | `azure-audit-microsoftstoragestorageaccountslocalusersregeneratepasswordaction` |


## Additive v7 bounded disclosure mappings (HackTricks Cloud 4913b6d88ced9972f72ccdd708d21641725a6fb5)

These additions cover terminal configuration disclosure on the exact reviewed resource. They do not establish a usable credential, downstream principal authority, application administration or chained permissions. Each requires fresh, bound metadata and effective source permission. Standard native disclosure adapters remain unavailable; missing evidence stays UNKNOWN. Historical rows above are retained.

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-static-web-apps-privesc.md#read-configured-third-party-credentials` | Terminal configuration disclosure: app services | Microsoft.Web/sourcecontrols/read | EXCLUDED | NEEDS SCHEMA: Exact GitHub or other source-control credential, subject, usability, and newly permitted action must be verified. |
| `az-privilege-escalation/az-service-fabric-privesc.md#cluster--client-certificate-theft--data-plane-admin` | Terminal configuration disclosure: service fabric | Microsoft.KeyVault/vaults/secrets/getSecret/action | EXCLUDED | Strict principal-boundary audit: Terminal secret/resource disclosure without a verified credential for an identified target principal or a grant of permissions to the caller. |
| `az-post-exploitation/az-service-connector-post-exploitation.md#read-connection-configuration-to-exfiltrate-the-backing-secret` | Terminal configuration disclosure: service linker | Microsoft.ServiceLinker/linkers/generateConfigurations/action, Microsoft.ServiceLinker/linkers/listConfigurations/action, Microsoft.ServiceLinker/linkers/read | EXCLUDED | Strict principal-boundary audit: Terminal secret/resource disclosure without a verified credential for an identified target principal or a grant of permissions to the caller. |
| `az-privilege-escalation/az-spring-apps-privesc.md#config-server--bindings--secret-exposure` | Terminal configuration disclosure: spring apps | Microsoft.AppPlatform/Spring/apps/bindings/read, Microsoft.AppPlatform/Spring/apps/read, Microsoft.AppPlatform/Spring/configService/read | EXCLUDED | Strict principal-boundary audit: Terminal secret/resource disclosure without a verified credential for an identified target principal or a grant of permissions to the caller. |
| `az-privilege-escalation/az-spring-apps-privesc.md#microsoftappplatformspringapmslistsecretkeysaction` | Terminal configuration disclosure: spring apps | Microsoft.AppPlatform/Spring/apms/listSecretKeys/action | EXCLUDED | Strict principal-boundary audit: Terminal secret/resource disclosure without a verified credential for an identified target principal or a grant of permissions to the caller. |
| `az-privilege-escalation/az-sre-agent-privesc.md#microsoftappagentsdataconnectorslistsecretsaction` | Terminal configuration disclosure: sre agent | Microsoft.App/agents/dataconnectors/listSecrets/action | EXCLUDED | Strict principal-boundary audit: Terminal secret/resource disclosure without a verified credential for an identified target principal or a grant of permissions to the caller. |
| `az-privilege-escalation/az-sre-agent-privesc.md#microsoftappagentslistsecretsaction` | Terminal configuration disclosure: sre agent | Microsoft.App/agents/listSecrets/action | EXCLUDED | Strict principal-boundary audit: Terminal secret/resource disclosure without a verified credential for an identified target principal or a grant of permissions to the caller. |

Semantic correction (2026-10-15): the historical Spring Apps `listSecretKeys` mapping above is retained for source traceability. Microsoft documents `Apms_ListSecretKeys` as returning sensitive property names, not secret values. Runtime explicitly suppresses its disclosure effect, including asserted reviewed metadata, and reports `sensitive_property_names_only`; this path remains unsupported. Reference: https://learn.microsoft.com/en-us/rest/api/azurespringapps/apms/list-secret-keys?view=rest-azurespringapps-2023-12-01

The same conservative review suppresses the historical Spring app/bindings, Service Linker, and two SRE agent disclosure mappings where the exact read operation does not establish a secret value. Write-only fields, redacted properties, Key Vault references, and a different action family cannot establish disclosure. The retained Fabric certificate path additionally requires explicit vault RBAC authorization; absent or access-policy mode remains UNKNOWN. Historical source mappings are not runtime support claims.


Current execution also suppresses the historical Spring bindings, Service Linker
and both legacy SRE disclosure effects because their exact returned credential
value semantics are unsupported. Source-control OAuth metadata and exportable
Fabric secret linkage remain bounded reviewed paths; Fabric requires an
explicit native RBAC-mode vault. These runtime corrections preserve every
historical MAPPED row and source revision; catalog inclusion is not a claim
of native evidence support or successful exploitation.

## Strict principal-boundary source reconciliation

The following rows map active techniques to their current HackTricks privilege-escalation sections. Excluded IDs and reasons are preserved in `peaso/privesc/catalog/azure/_excluded_strict_principal_boundary.yaml`.

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-api-management-privesc.md#microsoftapimanagementservicebackupaction--full-service-exfiltration-to-attacker-storage` | Restore a crafted backup over an APIM service to install identity-using policies | See catalog prerequisite actions | MAPPED | `azure-apim-restore-backup-managed-identity-token` |
| `az-privilege-escalation/az-api-management-privesc.md#microsoftapimanagementservicegatewaysgetconfigurationaction--bulk-policysecret-pull-data-action-bypasses-the-administrative-log` | APIM gateway configuration embedded credentials | See catalog prerequisite actions | MAPPED | `azure-apim-gateway-config-credential` |
| `az-privilege-escalation/az-api-management-privesc.md#microsoftapimanagementservicegatewayslistdebugcredentialsaction--servicegatewayslisttraceaction--live-requestresponse-wiretap` | Capture backend managed-identity tokens from APIM gateway request traces | See catalog prerequisite actions | EXCLUDED | NEEDS SCHEMA: Debug/trace permissions alone do not prove a particular existing policy used the named MI, a traced request ran, the Authorization header was unmasked, or a usable audience-bound token was received. |
| `az-privilege-escalation/az-api-management-privesc.md#microsoftapimanagementserviceloggerswrite--servicediagnosticswrite--persistent-traffic-exfil-to-attacker-event-hub` | Ship backend request headers to an attacker logger through APIM diagnostics | See catalog prerequisite actions | EXCLUDED | NEEDS SCHEMA: Logger and diagnostics writes alone do not prove the named MI was used by the exact API policy, matching traffic occurred, the backend Authorization header was captured, or a usable token was received. |
| `az-privilege-escalation/az-api-management-privesc.md#microsoftapimanagementservicetenantdeployaction--bulk-config-overwrite-via-built-in-git` | Deploy attacker policies through the APIM built-in Git configuration repository | See catalog prerequisite actions | MAPPED | `azure-apim-tenant-git-deploy-managed-identity-token` |
| `az-privilege-escalation/az-app-configuration-privesc.md#bulk-exfil--loot-persistence-via-snapshots-configurationstoressnapshotsread--write` | Recover credentials retained in App Configuration snapshot | See catalog prerequisite actions | MAPPED | `azure-appconfig-snapshot-credential` |
| `az-privilege-escalation/az-automation-accounts-privesc.md#harvest-secrets-from-prior-job-output-and-streams` | Read tokens and credentials from prior Automation job output | See catalog prerequisite actions | MAPPED | `azure-automation-job-output-credential` |
| `az-privilege-escalation/az-automation-accounts-privesc.md#read-runbook-source-for-hardcoded-secrets` | Read hardcoded credentials from runbook source | See catalog prerequisite actions | MAPPED | `azure-automation-runbook-source-credential` |
| `az-privilege-escalation/az-container-apps-privesc.md#microsoftappcontainerappssourcecontrolswrite--repoint-github-actions-deployment` | Repoint a Container App's GitHub Actions deployment to an attacker repository | See catalog prerequisite actions | MAPPED | `azure-containerapp-sourcecontrols-write` |
| `az-privilege-escalation/az-container-registry-privesc.md#microsoftcontainerregistryregistriespullread` | Extract credentials from ACR image layers | See catalog prerequisite actions | MAPPED | `azure-acr-layer-credential` |
| `az-privilege-escalation/az-container-registry-privesc.md#microsoftcontainerregistryregistriespushwrite-microsoftcontainerinstancecontainergroupsrestartaction` | Overwrite a registry image and restart the consuming container group | See catalog prerequisite actions | EXCLUDED | NEEDS SCHEMA: Registry push and a container-group restart do not prove the exact pushed image digest is consumed by that group, attacker code executed, or its attached identity was reached. |
| `az-privilege-escalation/az-dev-center-privesc.md#dev-center-environment-identity-deployment` | Bind a user-assigned identity to a project environment type and deploy with it | See catalog prerequisite actions | EXCLUDED | NEEDS SCHEMA: Identity assignment and environment creation rights do not prove exact dev-center attachment, enabled target, attacker-controlled ADE template, or a successful run as that UAMI. |
| `az-privilege-escalation/az-entra-id-governance-privesc.md#auto-assignment-policy-abuse-persistence` | Create an auto-assignment policy that keeps re-granting catalog groups | See catalog prerequisite actions | MAPPED | `azure-entraid-entitlement-auto-assignment-persistence` |
| `az-privilege-escalation/az-entraid-privesc/README.md#abusing-sync_-deprecated` | Directory Synchronization Accounts role holder resets user passwords through the sync API | See catalog prerequisite actions | EXCLUDED | `azure-entra-hybrid-directory-sync-role-password-reset` NEEDS SCHEMA: current accepted action, exact target reset, and usable credential are unverified. |
| `az-privilege-escalation/az-entraid-privesc/README.md#add-user-to-group` | Group owner adds itself to the owned group (incl. role-assignable groups) | See catalog prerequisite actions | MAPPED | `azure-entraid-group-owner-membership` |
| `az-privilege-escalation/az-entraid-privesc/README.md#federation---trusted-domain` | Federate a verified domain with an attacker-trusted issuer | See catalog prerequisite actions | MAPPED | `azure-entraid-domain-federation-backdoor` |
| `az-privilege-escalation/az-entraid-privesc/README.md#pivoting` | AAD DC Administrators member takes over Domain Services-joined VMs and their managed identities | See catalog prerequisite actions | EXCLUDED | `azure-entra-domain-services-dc-admins-vm-identity` NEEDS SCHEMA: exact execution or token retrieval for a named identity and a newly authorized action are unverified. |
| `az-privilege-escalation/az-entraid-privesc/README.md#principals-generated` | Directory Synchronization Accounts role holder adds credentials or privileges to service principals (historical) | See catalog prerequisite actions | EXCLUDED | `azure-entra-hybrid-directory-sync-role-sp-credentials` NEEDS SCHEMA: current accepted action, exact target change, and usable credential or grant are unverified. |
| `az-privilege-escalation/az-entraid-privesc/README.md#rogue-certificate-authority-in-the-tenant-cba-trust-store` | Trust an attacker certificate authority for certificate-based authentication | See catalog prerequisite actions | EXCLUDED | Trust-store write does not prove the exact target user's certificate binding, method scope, and usable certificate. |
| `az-privilege-escalation/az-intune-privesc.md#credential-access--filevault--bitlocker-keys--laps-passwords` | Read Windows LAPS passwords and take over the users of those devices | See catalog prerequisite actions | EXCLUDED | `azure-intune-laps-local-admin-device-user` NEEDS SCHEMA: usable LAPS credential, device reachability, and captured target-user session are unverified. |
| `az-privilege-escalation/az-kubernetes-privesc.md#flux-gitops-self-healing-foothold-fluxconfigurationswrite--sourcecontrolconfigurationswrite` | Point a Flux GitOps configuration at an attacker-controlled source | See catalog prerequisite actions | MAPPED | `azure-aks-flux-configuration-write` |
| `az-privilege-escalation/az-sql-privesc.md#sql-managed-instance-parity-and-clr-based-persistence` | Set the Azure SQL Managed Instance Entra administrator | See catalog prerequisite actions | MAPPED | `azure-sqlmi-entra-admin-write` `azure-sqlmi-admin-password-reset` |
| `az-privilege-escalation/az-storage-privesc.md#microsoftstoragestorageaccountsblobservicescontainersblobsread` | Read Entra credentials embedded in blobs | See catalog prerequisite actions | MAPPED | `azure-storage-blob-content-credential` |
| `az-privilege-escalation/az-virtual-desktop-privesc.md#fleet-rce-via-applicationgroupsapplicationswrite-lolbin-commandlinearguments` | Repoint a published AVD RemoteApp to run attacker commands on session hosts | See catalog prerequisite actions | EXCLUDED | Both historical AVD variants require exact RemoteApp launch, successful code execution, and a usable named user or host-identity token; the session-host variant previously had confidence unknown. |
| `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#reimage--redeploy-to-re-execute-poisoned-customdata` | Re-execute poisoned customData by reimaging or redeploying a VM | See catalog prerequisite actions | MAPPED | `azure-vm-customdata-reimage` |

## az-post-exploitation/az-service-configuration-disclosure.md (Kubernetes Writer disclosure addendum)

| Source (page#anchor, relative to src/pentesting-cloud/azure-security/) | Heading | Permissions | Status | Catalog mapping / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-service-configuration-disclosure.md#namespace-scoped-kubernetes-writer-secret-reads` | Namespace-Scoped Kubernetes Writer Secret Reads | AKS/Arc/Fleet Writer Secret read data actions | EXCLUDED | Generic Secret disclosure; the Secret must contain a verified usable credential bound to an exact subject before a principal edge exists. The distinct Pod-as-ServiceAccount route remains at `az-privilege-escalation/az-kubernetes-privesc.md#kubernetes-rbac-operations` as NEEDS SCHEMA. |

## az-post-exploitation/az-api-center-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-api-center-post-exploitation.md#internal-api-recon-data-reader` | Internal-API recon (Data Reader) |  | EXCLUDED | Data read of API metadata; no identity gained. |

## az-post-exploitation/az-communication-services-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-communication-services-post-exploitation.md#az---communication-services-post-exploitation` | Az - Communication Services Post Exploitation |  | STRUCTURAL | page title |
| `az-post-exploitation/az-communication-services-post-exploitation.md#communication-services` | Communication Services |  | STRUCTURAL | section introduction |
| `az-post-exploitation/az-communication-services-post-exploitation.md#org-domain-phishing-infrastructure-with-emailservicesdomainssenderusernameswrite` | Org-domain phishing infrastructure with `EmailServices/Domains/SenderUsernames/write` |  | EXCLUDED | Phishing infrastructure; no Azure identity. |
| `az-post-exploitation/az-communication-services-post-exploitation.md#push-channel-redirect-with-communicationserviceslinknotificationhubaction` | Push-channel redirect with `CommunicationServices/LinkNotificationHub/action` |  | EXCLUDED | Notification redirection; no Azure identity. |

## az-post-exploitation/az-fluid-relay-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-fluid-relay-post-exploitation.md#az---fluid-relay-post-exploitation` | Az - Fluid Relay Post Exploitation |  | STRUCTURAL | page title |
| `az-post-exploitation/az-fluid-relay-post-exploitation.md#fluid-relay` | Fluid Relay |  | STRUCTURAL | section introduction |
| `az-post-exploitation/az-fluid-relay-post-exploitation.md#container-id-enumeration-with-fluidrelaycontainersread` | Container-ID enumeration with `fluidRelayContainers/read` | Microsoft.FluidRelay/fluidRelayServers/fluidRelayContainers/read | EXCLUDED | Enumeration only. |
| `az-post-exploitation/az-fluid-relay-post-exploitation.md#cmkidentity-tamper-with-fluidrelayserverswrite` | CMK/identity tamper with `fluidRelayServers/write` | Microsoft.FluidRelay/fluidRelayServers/write | EXCLUDED | Service-side CMK identity use (DoS); no code path for the source. |

## az-post-exploitation/az-iot-hub-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-iot-hub-post-exploitation.md#az---iot-hub-post-exploitation` | Az - IoT Hub Post Exploitation |  | STRUCTURAL | page title |
| `az-post-exploitation/az-iot-hub-post-exploitation.md#iot-hub` | IoT Hub |  | STRUCTURAL | section introduction |
| `az-post-exploitation/az-iot-hub-post-exploitation.md#device-twin-disclosure-and-commandconfiguration-injection` | Device twin disclosure and command/configuration injection |  | EXCLUDED | Device configuration injection; device-side effect. |
| `az-post-exploitation/az-iot-hub-post-exploitation.md#cloud-to-device-messages-direct-methods-and-jobs` | Cloud-to-device messages, direct methods, and jobs |  | EXCLUDED | Device-side effect; no Azure identity. |
| `az-post-exploitation/az-iot-hub-post-exploitation.md#covert-built-in-events-consumer-group-with-eventhubendpointsconsumergroupswrite` | Covert built-in-events consumer group with `eventHubEndpoints/consumerGroups/Write` |  | EXCLUDED | Telemetry read and persistence; no new identity. |

## az-post-exploitation/az-notification-hubs-post-exploitation.md

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-post-exploitation/az-notification-hubs-post-exploitation.md#az---notification-hubs-post-exploitation` | Az - Notification Hubs Post Exploitation |  | STRUCTURAL | page title |
| `az-post-exploitation/az-notification-hubs-post-exploitation.md#notification-hubs` | Notification Hubs |  | STRUCTURAL | section introduction |
| `az-post-exploitation/az-notification-hubs-post-exploitation.md#key-less-push-with-notificationhubsdebugsendaction` | Key-less push with `NotificationHubs/debugSend/action` |  | EXCLUDED | Sends push notifications to devices; no identity gain. |

## Heading reconciliation (HackTricks Cloud `4fab4d35d179f490e5c0c6343ab7ef690b4a6f45`)

Headings added to `az-privilege-escalation/**` since the sweep above. Technique headings map to the current catalog ids below; repeated or bypass headings inherit their parent row.

| Key | Heading | Requirements | Status | Catalog ids / reason |
|---|---|---|---|---|
| `az-privilege-escalation/az-authorization-privesc.md#policy-assignment-remediation-with-an-existing-user-assigned-identity` | Policy assignment remediation with an existing user-assigned identity | See catalog prerequisite actions | MAPPED | `azure-policy-assignment-write-user-assigned-identity` |
| `az-privilege-escalation/az-automation-accounts-privesc.md#read-runbook-source-for-hardcoded-secrets-1` | Read runbook source for hardcoded secrets |  | SUBSECTION | repeated heading of #read-runbook-source-for-hardcoded-secrets: MAPPED `azure-automation-runbook-source-credential` |
| `az-privilege-escalation/az-automation-accounts-privesc.md#harvest-secrets-from-prior-job-output-and-streams-1` | Harvest secrets from prior job output and streams |  | SUBSECTION | repeated heading of #harvest-secrets-from-prior-job-output-and-streams: MAPPED `azure-automation-job-output-credential` |
| `az-privilege-escalation/az-cosmosDB-privesc.md#same-native-rbac-self-grant-on-the-other-cosmos-apis-cassandra--gremlin--table--mongodb-account` | Same native-RBAC self-grant on the other Cosmos APIs (Cassandra / Gremlin / Table / MongoDB account) | See catalog prerequisite actions | MAPPED | `azure-cosmos-other-api-role-assignment-write` |
| `az-privilege-escalation/az-data-factory-privesc.md#exchange-a-supplied-github-authorization-code-with-factoriesgetgithubaccesstokenaction` | Exchange a supplied GitHub authorization code with `factories/getGitHubAccessToken/action` | See catalog prerequisite actions | MAPPED | `azure-datafactory-github-oauth-external-principal` |
| `az-privilege-escalation/az-entraid-privesc/README.md#group-owner-joins-an-owned-group` | Group owner joins an owned group | See catalog prerequisite actions | MAPPED | `azure-entraid-group-owner-membership` |
| `az-privilege-escalation/az-entraid-privesc/az-conditional-access-policies-mfa-bypass.md#device-code-block-limited-to-selected-resources` | Device-code block limited to selected resources |  | SUBSECTION | of #conditional-access-policies-bypasses: EXCLUDED: Authentication-control bypass for an already-compromised credential; no new principal privileges. |
| `az-privilege-escalation/az-logic-apps-privesc.md#assign-a-user-assigned-identity-to-a-writable-workflow` | Assign a user-assigned identity to a writable workflow | See catalog prerequisite actions | MAPPED | `azure-logicapp-assign-user-assigned-identity` |
| `az-privilege-escalation/az-purview-privesc.md#microsoftpurviewaccountsaddrootcollectionadminaction--root-collection-administrator-grant` | `Microsoft.Purview/accounts/addrootcollectionadmin/action` — root collection administrator grant | See catalog prerequisite actions | MAPPED | `azure-purview-add-root-collection-admin` |
| `az-privilege-escalation/az-sql-privesc.md#reset-a-sql-server-administrator-password-with-microsoftsqlserverswrite` | Reset a SQL server administrator password with `Microsoft.Sql/servers/write` | See catalog prerequisite actions | MAPPED | `azure-sql-server-admin-password-reset` |
| `az-privilege-escalation/az-sql-privesc.md#reset-a-sql-managed-instance-administrator-password` | Reset a SQL Managed Instance administrator password | See catalog prerequisite actions | MAPPED | `azure-sqlmi-admin-password-reset` |
| `az-privilege-escalation/az-sql-privesc.md#set-a-sql-managed-instance-entra-administrator` | Set a SQL Managed Instance Entra administrator | See catalog prerequisite actions | MAPPED | `azure-sqlmi-entra-admin-write` |
| `az-privilege-escalation/az-sql-privesc.md#set-a-sql-server-entra-administrator-with-microsoftsqlserversadministratorswrite` | Set a SQL server Entra administrator with `Microsoft.Sql/servers/administrators/write` | See catalog prerequisite actions | MAPPED | `azure-sql-server-entra-admin-write` |
| `az-privilege-escalation/az-storage-privesc.md#read-a-verified-credential-from-a-blob` | Read a verified credential from a blob | See catalog prerequisite actions | MAPPED | `azure-storage-blob-content-credential` |
| `az-privilege-escalation/az-virtual-machines-and-network-privesc.md#reimage-a-vm-with-new-customdata` | Reimage a VM with new customData | See catalog prerequisite actions | MAPPED | `azure-vm-customdata-reimage` |
| `az-privilege-escalation/az-vmware-solution-avs-privesc.md#run-command-identity-grants-without-reading-credentials-scriptexecutionswrite` | Run Command identity grants without reading credentials (`scriptExecutions/write`) | See catalog prerequisite actions | MAPPED | `azure-avs-run-command-vcenter-grant-external-principal` |

## Current CSPM catalog reconciliation (HackTricks Cloud `4fab4d35d179f490e5c0c6343ab7ef690b4a6f45`)

The heading sweep above records its historical source revision. The rows below record every current Azure automatic technique and the main-only paths retired from automatic evaluation. RETIRED entries remain documented in the source and exclusion catalog; they do not run as automatic checks.

| Technique ID | Source | Current disposition | Reason |
| --- | --- | --- | --- |
| `azure-aci-assign-user-assigned-identity` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#microsoftresourcessubscriptionsresourcegroupsread-microsoftcontainerinstancecontainergroupswrite-microsoftmanagedidentityuserassignedidentitiesassignaction` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-aci-container-exec` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#microsoftcontainerinstancecontainergroupsread-microsoftcontainerinstancecontainergroupscontainersexecaction` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-aci-containergroup-write-existing` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#microsoftcontainerinstancecontainergroupswrite-environment-update` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-acr-layer-credential` | `src/pentesting-cloud/azure-security/az-post-exploitation/az-container-registry-post-exploitation.md#microsoftcontainerregistryregistriespullread` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-acr-task-assign-user-assigned-identity` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-container-registry-privesc.md#microsoftcontainerregistryregistriestaskswrite` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-acr-task-write-existing-identity` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-container-registry-privesc.md#microsoftcontainerregistryregistriestaskswrite` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-aks-access-profile-list-credential` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-kubernetes-privesc.md#alternative-cluster-credential-retrieval-apis` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-aks-azure-rbac-impersonate` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-kubernetes-privesc.md#kubernetes-rbac-operations` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-aks-azure-rbac-k8s-rbac-write` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-kubernetes-privesc.md#kubernetes-rbac-operations` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-aks-flux-configuration-write` | `src/pentesting-cloud/azure-security/az-persistence/az-kubernetes-persistence.md#flux-gitops-self-healing-foothold-fluxconfigurationswrite--sourcecontrolconfigurationswrite` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-aks-list-cluster-admin-credential` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-kubernetes-privesc.md#aks-cluster-credentials` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-aks-list-cluster-user-credential` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-kubernetes-privesc.md#aks-cluster-credentials` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-aks-managedclusters-write-enable-local-accounts` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-kubernetes-privesc.md#re-arm-the-built-in-cluster-admin--graft-an-attacker-entra-admin-group-managedclusterswrite` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-aks-run-command` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-kubernetes-privesc.md#run-command--in-cluster-execution-with-no-kubeconfig-and-no-network-line-of-sight` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-aks-vmss-node-run-command` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-kubernetes-privesc.md#vm-scale-set-run-command-on-aks-workers` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-analysisservices-server-admin-write` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-analysis-services-privesc.md#server-admin-self-add--full-model-exfil-marquee` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-apim-developer-portal-shared-token-external-principal` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-api-management-privesc.md#microsoftapimanagementserviceuserstokenaction` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-apim-developer-portal-sso-external-principal` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-api-management-privesc.md#microsoftapimanagementserviceusersgeneratessourlaction` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-apim-gateway-config-credential` | `src/pentesting-cloud/azure-security/az-post-exploitation/az-api-management-post-exploitation.md#microsoftapimanagementservicegatewaysgetconfigurationaction--bulk-policysecret-pull-data-action-bypasses-the-administrative-log` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-apim-policy-write-managed-identity-token` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-api-management-privesc.md#microsoftapimanagementserviceapispolicieswrite--steal-the-apim-managed-identity-token` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-apim-restore-backup-managed-identity-token` | `src/pentesting-cloud/azure-security/az-post-exploitation/az-api-management-post-exploitation.md#microsoftapimanagementservicebackupaction--full-service-exfiltration-to-attacker-storage` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-appconfig-snapshot-credential` | `src/pentesting-cloud/azure-security/az-post-exploitation/az-app-configuration-post-exploitation.md#bulk-exfil--loot-persistence-via-snapshots-configurationstoressnapshotsread--write` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-appservice-assign-user-assigned-identity` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-app-services-privesc.md#microsoftwebsiteswrite-microsoftwebsitesread-microsoftmanagedidentityuserassignedidentitiesassignaction` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-appservice-config-write` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-app-services-privesc.md#microsoftwebsitesconfigwrite` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-appservice-kudu-publish-action` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-app-services-privesc.md#microsoftwebsitespublishaction-and-microsoftwebsitesslotspublishaction` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-appservice-onedeploy-extensions-write` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-app-services-privesc.md#microsoftwebsitesextensionswrite--onedeploy-zip-replacement` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-appservice-publishing-credentials-basic-auth-enabled` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-app-services-privesc.md#publish-code-using-scm-credentials` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-appservice-publishing-credentials-enable-basic-auth` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-app-services-privesc.md#obtaining-scm-credentials--enabling-basic-authentication` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-appservice-restore-from-backup-blob` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-app-services-privesc.md#microsoftwebsitesrestorefrombackupblobaction--restore-an-attacker-backup` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-appservice-sitecontainers-write` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-app-services-privesc.md#microsoftwebsitessitecontainerswrite-and-microsoftwebsitesslotssitecontainerswrite` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-appservice-siteextensions-write` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-app-services-privesc.md#microsoftwebsitessiteextensionswrite--attacker-nuget-site-extension` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-appservice-slot-code-execution` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-app-services-privesc.md#microsoftwebsitesslotsconfigwrite--recycle-a-deployment-slot-into-attacker-code` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-appservice-slot-publishxml` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-functions-app-privesc.md#microsoftwebsitesslotspublishxmlaction` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-appservice-slot-swap-promote-code` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-app-services-privesc.md#microsoftwebsitesslotsswapaction-promote-staged-code--steal-production-sticky-secrets` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-appservice-sourcecontrols-write` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-app-services-privesc.md#microsoftwebsitessourcecontrolswrite-and-microsoftwebsitesslotssourcecontrolswrite` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-arc-hybrid-connectivity-entra-ssh` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-arc-enabled-servers-privesc.md#sshrdp-to-arc-machines-via-hybrid-connectivity` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-arc-machine-extensions-write` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-arc-enabled-servers-privesc.md#rce--persistence-via-vm-extensions-custom-script` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-arc-machine-runcommands-write` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-arc-enabled-servers-privesc.md#rce-via-arc-run-command` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-arc-resource-bridge-credential-export` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-arc-resource-bridge-privesc.md#export-customer-kubeconfig-and-ssh-credentials` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-arm-deploymentscript-with-user-assigned-identity` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-arm-deployment-privesc.md#microsoftresourcesdeploymentscriptswrite` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-aro-list-admin-credentials` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-kubernetes-privesc.md#azure-red-hat-openshift-aro-cluster-credentials` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-aro-list-credentials` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-kubernetes-privesc.md#azure-red-hat-openshift-aro-cluster-credentials` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-audit-microsoftstoragestorageaccountslocalusersregeneratepasswordaction` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-storage-privesc.md#microsoftstoragestorageaccountslocalusersregeneratepasswordaction` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-audit-microsoftstoragestorageaccountslocaluserswrite-microsoftstoragestorageac` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-storage-privesc.md#microsoftstoragestorageaccountslocaluserswrite-microsoftstoragestorageaccountslocalusersread` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-audit-microsoftwebstaticsiteslistsecretsaction` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-static-web-apps-privesc.md#microsoftwebstaticsiteslistsecretsaction` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-authorization-elevateaccess-global-admin` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-authorization-privesc.md#microsoftauthorizationelevateaccessaction` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-authorization-elevateaccess-pim-eligible-global-admin` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-authorization-privesc.md#microsoftauthorizationelevateaccessaction` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-automation-assign-user-assigned-identity` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-automation-accounts-privesc.md#microsoftautomationautomationaccountswrite-microsoftmanagedidentityuserassignedidentitiesassignaction` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-automation-job-output-credential` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-automation-accounts-privesc.md#harvest-secrets-from-prior-job-output-and-streams` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-automation-runbook-author-and-run` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-automation-accounts-privesc.md#microsoftautomationautomationaccountsjobswrite-microsoftautomationautomationaccountsrunbooksdraftwrite-microsoftautomationautomationaccountsrunbooksdraftcontentwrite-microsoftautomationautomationaccountsjobsoutputread-microsoftautomationautomationaccountsrunbookspublishaction-microsoftresourcessubscriptionsresourcegroupsread-microsoftautomationautomationaccountsrunbookswrite` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-automation-runbook-hybrid-worker` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-automation-accounts-privesc.md#hybrid-workers-group` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-automation-runbook-source-credential` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-automation-accounts-privesc.md#read-runbook-source-for-hardcoded-secrets` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-avs-list-nsxt-admin-external-principal` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-vmware-solution-avs-privesc.md#cloudadmin--nsx-t-credential-disclosure-listadmincredentials` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-avs-list-vcenter-cloudadmin-external-principal` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-vmware-solution-avs-privesc.md#cloudadmin--nsx-t-credential-disclosure-listadmincredentials` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-avs-run-command-vcenter-grant-external-principal` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-vmware-solution-avs-privesc.md#run-command-identity-grants-without-reading-credentials-scriptexecutionswrite` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-batch-job-task-submission` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-batch-privesc.md#azure-batch-job-and-task-data-actions` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-batch-pool-write-assign-user-assigned-identity` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-batch-privesc.md#microsoftbatchbatchaccountspoolswrite--node-rce-via-pool-starttask--managed-identity-attach-control-plane-no-keys` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-batch-pool-write-starttask` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-batch-privesc.md#microsoftbatchbatchaccountspoolswrite--node-rce-via-pool-starttask--managed-identity-attach-control-plane-no-keys` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-batch-shared-key-task-submission` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-batch-privesc.md#microsoftbatchbatchaccountslistkeysaction` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-confidentialledger-ledgers-write-principal` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-confidential-ledger-privesc.md#data-plane-role-self-grant-via-ledgerswrite` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-containerapp-assign-user-assigned-identity` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#microsoftappcontainerappswrite-microsoftmanagedidentityuserassignedidentitiesassignaction` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-containerapp-create-with-user-assigned-identity` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#microsoftappcontainerappswrite-microsoftmanagedidentityuserassignedidentitiesassignaction-microsoftappmanagedenvironmentsjoinaction` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-containerapp-exec` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#microsoftappcontainerappsread-microsoftappmanagedenvironmentsread-microsoftappcontainerappsrevisionsreplicasread-microsoftappcontainerappsrevisionsread-microsoftappcontainerappsgetauthtokenaction-microsoftappcontainerappsexecaction-microsoftappcontainerappsdebugaction` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-containerapp-job-assign-user-assigned-identity` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#microsoftmanagedidentityuserassignedidentitiesassignaction-microsoftappjobswrite` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-containerapp-job-start-template-override` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#microsoftappjobsstartaction-microsoftappjobsread` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-containerapp-sourcecontrols-write` | `src/pentesting-cloud/azure-security/az-persistence/az-container-apps-persistence.md#microsoftappcontainerappssourcecontrolswrite--repoint-github-actions-deployment` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-containerapp-write-existing` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-container-instances-apps-jobs-privesc.md#microsoftappcontainerappswrite` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-cosmos-mongocluster-admin-password` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-cosmosDB-privesc.md#microsoftdocumentdbmongoclustersread--microsoftdocumentdbmongoclusterswrite` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-cosmos-mongocluster-user-write` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-cosmosDB-privesc.md#microsoftdocumentdbmongoclusterslistconnectionstringsaction--mongoclustersusersread--userswrite` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-cosmos-mongodb-user-definition-write` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-cosmosDB-privesc.md#microsoftdocumentdbdatabaseaccountsmongodbroledefinitionswrite--microsoftdocumentdbdatabaseaccountsmongodbroledefinitionsread-microsoftdocumentdbdatabaseaccountsmongodbuserdefinitionswrite--microsoftdocumentdbdatabaseaccountsmongodbuserdefinitionsread` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-cosmos-other-api-role-assignment-write` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-cosmosDB-privesc.md#same-native-rbac-self-grant-on-the-other-cosmos-apis-cassandra--gremlin--table--mongodb-account` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-cosmos-sql-role-assignment-write` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-cosmosDB-privesc.md#microsoftdocumentdbdatabaseaccountssqlroledefinitionswrite-microsoftdocumentdbdatabaseaccountssqlroledefinitionsread--microsoftdocumentdbdatabaseaccountssqlroleassignmentswrite-microsoftdocumentdbdatabaseaccountssqlroleassignmentsread` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-databricks-assign-workspace-admin` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-databricks-privesc.md#become-a-workspace-admin-through-azure-rbac` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-datafactory-github-oauth-external-principal` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-data-factory-privesc.md#exchange-a-supplied-github-authorization-code-with-factoriesgetgithubaccesstokenaction` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-devtestlabs-apply-artifacts` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-devtest-labs-privesc.md#applyartifacts--in-guest-rce--managed-identity-theft-marquee` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-entraid-agent-blueprint-credentials` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-entraid-privesc/README.md#entra-agent-id-blueprint-credential-abuse-agentidentityblueprintaddremovecredsall` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-entraid-app-credentials-update` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectoryapplicationscredentialsupdate` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-entraid-app-myorg-credentials-update` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectoryapplicationsmyorganizationallpropertiesupdate` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-entraid-app-owner-credentials` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectoryapplicationsownersupdate` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-entraid-app-owners-update` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectoryapplicationsownersupdate` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-entraid-custom-role-definition-update` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-entraid-privesc/README.md#role-privileged-role-administrator` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-entraid-domain-federation-backdoor` | `src/pentesting-cloud/azure-security/az-persistence/README.md#federation---trusted-domain` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-entraid-entitlement-auto-assignment-persistence` | `src/pentesting-cloud/azure-security/az-persistence/az-entra-id-governance-persistence.md#auto-assignment-policy-abuse-persistence` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-entraid-entitlement-catalog-self-grant-group` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-entra-id-governance-privesc.md#catalog-scoped-self-grant-privesc` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-entraid-entitlement-catalog-self-grant-role` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-entra-id-governance-privesc.md#catalog-scoped-self-grant-privesc` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-entraid-graph-application-readwrite-all` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-entraid-privesc/README.md#applicationreadwriteall` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-entraid-graph-approleassignment-readwrite-all` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-entraid-privesc/README.md#approleassignmentreadwriteall` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-entraid-graph-group-readwrite-all` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-entraid-privesc/README.md#sensitive-graph-permissions` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-entraid-graph-group-readwrite-all-controlled-user` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-entraid-privesc/README.md#sensitive-graph-permissions` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-entraid-graph-pim-groups-active-assignment` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-pim-privesc.md#pim-for-groups-the-sneaky-path` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-entraid-graph-pim-groups-eligibility` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-entraid-privesc/README.md#other-high-impact-microsoft-graph-permissions-directoryreadwriteall-groupmemberreadwriteall-synchronizationreadwriteall-privilegedeligibilityschedulereadwriteazureadgroup` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-entraid-graph-rolemanagement-readwrite-directory` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-entraid-privesc/README.md#rolemanagementreadwritedirectory` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-entraid-graph-userauthenticationmethod-tap` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-entraid-privesc/README.md#userauthenticationmethodreadwriteall` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-entraid-group-dynamic-rule-update` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectorygroupsdynamicmembershipruleupdate` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-entraid-group-members-update` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectorygroupsmembersupdate` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-entraid-group-owner-membership` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-entraid-privesc/README.md#group-owner-joins-an-owned-group` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-entraid-group-owners-update` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectorygroupsownersupdate` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-entraid-pim-eligible-role-activation` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-pim-privesc.md#activate-an-eligible-role-in-model-jit-self-elevation` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-entraid-pim-group-eligible-activation` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-pim-privesc.md#pim-for-groups-the-sneaky-path` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-entraid-reset-credentials-authentication-admin` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectoryuserspasswordupdate` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-entraid-reset-credentials-privileged-auth-admin` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectoryuserspasswordupdate` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-entraid-reset-password-helpdesk-admin` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectoryuserspasswordupdate` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-entraid-reset-password-partner-tier1` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectoryuserspasswordupdate` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-entraid-reset-password-password-admin` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectoryuserspasswordupdate` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-entraid-reset-password-user-admin` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectoryuserspasswordupdate` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-entraid-role-assignment-manage` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-entraid-privesc/README.md#role-privileged-role-administrator` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-entraid-sp-credentials-update` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectoryserviceprincipalscredentialsupdate` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-entraid-sp-owner-credentials` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectoryserviceprincipalsownersupdate` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-entraid-sp-owners-update` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-entraid-privesc/README.md#microsoftdirectoryserviceprincipalsownersupdate` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-eventgrid-mqtt-client-grant-external-principal` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-event-grid-privesc.md#backdoor-mqtt-client-via-namespacesclients--clientgroups--permissionbindingswrite` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-functions-functions-write` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-app-services-privesc.md#replace-a-functions-code-with-microsoftwebsitesfunctionswrite` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-functions-hostruntime-vfs-write` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-functions-app-privesc.md#microsoftwebsiteshostruntimevfswrite` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-functions-remote-debugging` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-functions-app-privesc.md#remote-debugging` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-functions-sites-write-source-control` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-functions-app-privesc.md#change-github-repo` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-grafana-act-as-admin` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-managed-grafana-privesc.md#microsoftdashboardgrafanaactasgrafanaadminaction` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-guestconfiguration-assignment-write-arc` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-guest-configuration-privesc.md#in-guest-rce-via-a-guest-configuration-assignment-marquee` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-hybrid-k8s-list-cluster-admin-credential` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-kubernetes-privesc.md#aks-cluster-credentials` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-imagebuilder-template-create-via-template-identity` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-image-builder-privesc.md#customizer-rce--build-identity-token-theft-marquee` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-kusto-cluster-principal-assignment-write` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-data-explorer-privesc.md#cluster-wide-variant-microsoftkustoclustersprincipalassignmentswrite` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-kusto-database-add-principals` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-data-explorer-privesc.md#microsoftkustoclustersdatabasesaddprincipalsaction--direct-principal-add-stealthier-than-principalassignments` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-kusto-database-principal-assignment-write` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-data-explorer-privesc.md#microsoftkustoclustersdatabasesprincipalassignmentswrite` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-loadtesting-assign-user-assigned-identity` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-load-testing-privesc.md#test-engine-rce--managed-identity-token-theft-marquee` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-loadtesting-test-engine-identity` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-load-testing-privesc.md#test-engine-rce--managed-identity-token-theft-marquee` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-logicapp-assign-user-assigned-identity` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-logic-apps-privesc.md#assign-a-user-assigned-identity-to-a-writable-workflow` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-logicapp-workflow-write-existing-identity` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-logic-apps-privesc.md#microsoftlogicworkflowswrite` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-managedapp-list-tokens` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-managed-applications-privesc.md#listtokens--cross-tenant-managed-identity-token-export-marquee` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-managedidentity-federated-credential-write` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-authorization-privesc.md#microsoftmanagedidentityuserassignedidentitiesfederatedidentitycredentialswrite` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-ml-compute-application-access` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-ai-foundry-privesc.md#microsoftmachinelearningservicesworkspacesread--microsoftmachinelearningservicesworkspacescomputesapplicationaccessaction` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-ml-compute-create-with-user-assigned-identity` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-ai-foundry-privesc.md#microsoftmachinelearningservicesworkspacescomputeswrite` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-ml-online-deployment-existing-endpoint` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-ai-foundry-privesc.md#microsoftmachinelearningservicesworkspacesonlineendpointswrite-microsoftmachinelearningservicesworkspacesonlineendpointsdeploymentswrite-microsoftmachinelearningservicesworkspacesread` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-ml-online-endpoint-create-with-user-assigned-identity` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-ai-foundry-privesc.md#microsoftmachinelearningservicesworkspacesonlineendpointswrite-microsoftmachinelearningservicesworkspacesonlineendpointsdeploymentswrite-microsoftmachinelearningservicesworkspacesread` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-mysql-flexible-admin-password-reset` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-mysql-privesc.md#microsoftdbformysqlflexibleserversread--microsoftdbformysqlflexibleserverswrite--microsoftdbformysqlflexibleserversdelete` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-mysql-flexible-entra-admin-write` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-mysql-privesc.md#microsoftdbformysqlflexibleserversread-microsoftdbformysqlflexibleserverswrite-microsoftmanagedidentityuserassignedidentitiesassignaction-microsoftdbformysqlflexibleserversadministratorswrite--microsoftdbformysqlflexibleserversadministratorsread` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-policy-assignment-write-user-assigned-identity` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-authorization-privesc.md#policy-assignment-remediation-with-an-existing-user-assigned-identity` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-postgresql-flexible-admin-password-reset` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-postgresql-privesc.md#microsoftdbforpostgresqlflexibleserversread-microsoftdbforpostgresqlflexibleserverswrite-microsoftdbforpostgresqlflexibleserversconfigurationswrite` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-postgresql-flexible-entra-admin-write` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-postgresql-privesc.md#microsoftdbforpostgresqlflexibleserversread-microsoftdbforpostgresqlflexibleserverswrite-microsoftdbforpostgresqlflexibleserversadministratorswrite--microsoftdbforpostgresqlflexibleserversadministratorsread` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-purview-add-root-collection-admin` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-purview-privesc.md#microsoftpurviewaccountsaddrootcollectionadminaction--root-collection-administrator-grant` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-purview-policy-self-grant` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-purview-privesc.md#microsoftpurviewpolicyelementswrite--purview-access-policies-into-governed-sqlstorage` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-servicefabric-application-user-assigned-identity` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-service-fabric-privesc.md#managed-identity-token-theft-via-the-sf-token-service` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-springapps-app-write-user-assigned-identity` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-spring-apps-privesc.md#app-deploy-rce--managed-identity-theft-marquee` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-springapps-deployment-write-app-identity` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-spring-apps-privesc.md#app-deploy-rce--managed-identity-theft-marquee` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-sql-server-admin-password-reset` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-sql-privesc.md#reset-a-sql-server-administrator-password-with-microsoftsqlserverswrite` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-sql-server-entra-admin-write` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-sql-privesc.md#set-a-sql-server-entra-administrator-with-microsoftsqlserversadministratorswrite` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-sqlmi-admin-password-reset` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-sql-privesc.md#reset-a-sql-managed-instance-administrator-password` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-sqlmi-entra-admin-write` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-sql-privesc.md#set-a-sql-managed-instance-entra-administrator` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-storage-adls-acl-self-grant` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-storage-privesc.md#hns-acl-takeover-and-blob-super-user-data-action` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-storage-blob-content-credential` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-storage-privesc.md#read-a-verified-credential-from-a-blob` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-storage-files-acl-self-grant` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-storage-privesc.md#microsoftstoragestorageaccountsfileservicesfilesharesfilesmodifypermissionsaction` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-storage-local-user-create-with-sftp-access` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-storage-privesc.md#microsoftstoragestorageaccountslocaluserswrite-microsoftstoragestorageaccountslocalusersread` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-synapse-entra-admin-write` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-synapse-privesc.md#replace-the-workspace-microsoft-entra-administrator` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-vm-assign-user-assigned-identity-existing` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputevirtualmachineswrite-microsoftmanagedidentityuserassignedidentitiesassignaction` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-vm-assign-user-assigned-identity-indirect-exec` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputevirtualmachineswrite-microsoftmanagedidentityuserassignedidentitiesassignaction` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-vm-create-with-user-assigned-identity` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftresourcesdeploymentswrite-microsoftnetworkvirtualnetworkswrite-microsoftnetworknetworksecuritygroupswrite-microsoftnetworknetworksecuritygroupsjoinaction-microsoftnetworkpublicipaddresseswrite-microsoftnetworkpublicipaddressesjoinaction-microsoftnetworknetworkinterfaceswrite-microsoftcomputevirtualmachineswrite-microsoftnetworkvirtualnetworkssubnetsjoinaction-microsoftnetworknetworkinterfacesjoinaction-microsoftmanagedidentityuserassignedidentitiesassignaction` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-vm-customdata-reimage` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-virtual-machines-and-network-privesc.md#reimage-a-vm-with-new-customdata` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-vm-extensions-write` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputevirtualmachinesextensionswrite` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-vm-gallery-application-install` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputegallerieswrite-microsoftcomputegalleriesapplicationswrite-microsoftcomputegalleriesapplicationsversionswrite-microsoftcomputevirtualmachineswrite` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-vm-managed-runcommands-write` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputevirtualmachinesruncommandswrite` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-vm-os-disk-swap` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputevirtualmachineswrite-os-disk-swap` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-vm-runcommand-action` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputevirtualmachinesruncommandaction` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-vmss-model-write` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputevirtualmachinescalesetswrite-scale-set-model-tampering` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-vmss-vm-managed-runcommands-write` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputevirtualmachinesruncommandswrite` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-vmss-vm-runcommand-action` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-virtual-machines-and-network-privesc.md#microsoftcomputevirtualmachinesruncommandaction` | ACTIVE | Reviewed source-bound automatic path. |
| `azure-apim-tenant-git-deploy-managed-identity-token` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-api-management-privesc.md#microsoftapimanagementservicetenantdeployaction--bulk-config-overwrite-via-built-in-git` | RETIRED | Microsoft retired the built-in API Management Git save/deploy feature after 15 March 2025, so tenant deploy plus listSecrets no longer establishes a policy-install path. |
| `azure-datafactory-dataplane-access-token` | `src/pentesting-cloud/azure-security/az-privilege-escalation/az-data-factory-privesc.md#mint-a-factory-data-plane-access-token-with-factoriesgetdataplaneaccessaction` | RETIRED | The target selector requires externally reviewed evidence of a usable data-plane token, a runnable pipeline, successful run, and an obtained managed-identity token. The scanner cannot safely perform these active steps from the management permission alone; synthetic positive/negative tests cover only supplied proof. |
| `azure-service-linker-read-connection-configuration-to-exfiltrate-the-backing-secret` | `src/pentesting-cloud/azure-security/az-post-exploitation/az-service-connector-post-exploitation.md#read-connection-configuration-to-exfiltrate-the-backing-secret` | RETIRED | Service Connector configuration reads may disclose connection strings, but the target is modeled as data-plane admin without a typed exact credential subject or authorization proof. The old reviewed strict-principal-boundary exclusion classifies this as terminal secret disclosure, not a privilege-escalation edge. |
