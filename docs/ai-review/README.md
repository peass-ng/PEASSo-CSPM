Hosted runtime: [role-free Fargate isolation, deployment wiring and live smoke](hosted-isolation.md).

# Post-scan Chack review

Shell-enabled hosted reviews use the role-free Fargate isolation backend. A usable AI configuration and the deployed isolation runtime are required. See [hosted isolation and deployment acceptance](hosted-isolation.md) for the credential boundary and live verification steps.

## What runs

Hardening and Exposure reviewers receive scope-bound collection receipts alongside
referenced resources. An explicitly empty, complete inventory can establish that
a required configuration is absent; denied or partial inventory cannot. These
receipts contain only type, scope, status and counts, are bounded once per batch,
and participate in review reuse fingerprints so changed coverage is rechecked.

AI defaults to `true` in `ScanCreate` and schedules. The launch form can disable it. Existing schedules without a flag inherit `true`.

Settings → AI review also provides **Disable AI for every scan**, in both hosted
and on-premise deployments. This account-wide override applies in every workspace,
including existing schedules and queued scans.
It prevents new AI agent launches and retains saved provider credentials and each
schedule's selection. Disabling needs no provider validation; enabling restores
the usual per-scan selections and mandatory launch-time credential validation.
It does not terminate an agent that was already running when the preference changed.
The setting is stored independently as non-secret account metadata, so checking it
does not require loading an AI credential or encryption key.

**Sign in with Codex** starts device authentication on the backend and shows the
OpenAI login link and one-time code in Settings. Open that link on your laptop,
enter the code and finish signing in; CSPM polls for completion and stores returned
tokens encrypted. Then choose the model and thinking effort and validate/save the
selection. No localhost callback or CLI installation is required on your laptop.

After deterministic analysis, Chack reviews failed Hardening and Exposure findings and runs a holistic Network agent in the same bounded parallel pool, then produces up to 15 prioritized actions. Priorities runs alone after all three types finish, receiving their final verdicts and new network findings. It starts with a complete compact `platform.json` decision brief and uses `context.py` for indexed lookups in `context.sqlite`. Its full evidence covers all security areas; the Network agent gets a separate network-only database and topology catalog. Each Hardening/Exposure verifier receives one `findings.json`: `scan` holds the scan identity/time and `items` contains only its assigned failed checks. Each check retains its evidence and has `supporting_resources` containing only native resource records explicitly referenced by that check. There is no separate evidence file. Verifiers receive no full report, inventory, graphs, least-privilege projection or other review batches. Credentials are selected by provider and referenced accounts, projects, subscriptions or cluster. Target lists narrow the handoff and instructions, not the provider permissions of the captured token. Agents do not need a platform administrator API token.

Both selection and the file-writing boundary enforce that findings.json contains only FAIL checks in the assigned category. Passed, unresolved, denied, manual, empty and inapplicable checks are excluded.

Findings of one check, scope and resource type whose evidence is identical apart from their own resource identifiers form a group; only the group's first finding is sent to the reviewer. A confirmed FAIL is copied to the other members, while any other verdict sends each remaining member to its own review in the same pool, so a native failure is only overturned on that finding's own document. Findings without evidence are never grouped. Reviews run in balanced batches of at most 40, alternating Hardening and Exposure so both progress. Local concurrency defaults to two; the AWS deployment configures twelve, subject to the same memory admission checks. Its shared AI budget is 3,000 seconds, including Fargate startup and input preparation, and the scan deadline remains authoritative. The invocation’s remaining budget also configures the inner wrapper. Individual reviewer tasks remain bounded to 480 seconds, Network to 900 seconds and Priorities to 1,500 seconds, all below the 1,800-second task limit. On AWS, up to 300 seconds (at most a quarter of the time left) before the scan deadline are kept for the final report publication. Results retain their category and finding order; exact duplicates run once. Unprocessed or failed batches get explicit UNKNOWN results and partial AI status. Priorities waits for every active task to finish and clean up, with up to 600 seconds reserved on AWS and 60 seconds locally. Deterministic findings remain available when AI fails.

Exposure is deduplicated only when its check ID, resource ID and scope exactly match a Hardening observation. Sharing an account or resource alone is not enough. A duplicate reuses the original review under its own finding ID. Distinct controls continue through the Exposure reviewer.

Validated AI verdicts are applied to the existing Hardening and Exposure finding views before filtering, grouping and counting. Native evidence is preserved, with the original scanner status retained as `scanner_status` and the AI explanation attached to the finding. Failed or unavailable review attempts keep the scanner result. Existing reports receive the same projection when read. Each review retains its exact finding reference; unsupported or foreign references cannot change another finding.

## Local review files

- [Hardening Chack YAML](../../peaso/ai/agents/hardening.yaml)
- [Exposure Chack YAML](../../peaso/ai/agents/exposure.yaml)
- [Network Chack YAML](../../peaso/ai/agents/network.yaml)
- [Network output JSON Schema](../../peaso/ai/network.schema.json)
- [Prioritization Chack YAML](../../peaso/ai/agents/priorities.yaml)
- [Per-invocation access instruction builder](../../peaso/ai/prompting.py)
- [Review JSON Schema](../../peaso/ai/reviews.schema.json)
- [Action-table JSON Schema](../../peaso/ai/recommendations.schema.json)
- [Illustrative result](example-result.json), using synthetic IDs and evidence

Each task prompt follows the sectioned style of the existing FactChecker verifier, Trip Planner administrator and organization-recon Chack prompts: PERSONALITY, GOAL, INPUTS, GUIDELINES, WORKFLOW, OUTPUT and EXAMPLES. The user prompt has an AVAILABLE ACCESS section populated only from that invocation's credential entries. Instructions use natural language with good and bad examples. Pydantic validates output shape and cross references: exact review coverage, distinct IDs, supported verdicts and 500-character reasons, existing resource/finding references, consecutive ranks, at most 15 actions, and brief rationale/steps/verification fields. Findings reviewed as PASS, NOT_APPLICABLE or EMPTY cannot be recommended as outstanding remediation. The agents do not execute the proposed changes.

Recommendations use six fields per action: `rank`, `title`, `finding_ids`, `rationale`, `steps` and `verification`. Rationale combines decisive facts, expected benefit and action-specific uncertainty (1000 characters maximum). There are at most five steps of 500 characters each and a 700-character verification instruction. Necessary prerequisites and rollout cautions belong in steps; common limitations stay at the top level. Rank supplies the ordering, and finding references identify affected targets. Supporting evidence lists finding titles that open their details while keeping the action plan open. Separate priority, scope, provider, impact, effort, owner, dependency, rollback and evidence fields are no longer requested.

The dispatch pool runs inside the analyzer. Hosted invocations each use a separate role-free Fargate task; local invocations use the configured isolation launcher. It checks host-available RAM and Linux cgroup v1/v2 remaining memory before admitting more work, reserving 128 MiB of free headroom plus an estimated 512 MiB per local agent or 256 MiB of analyzer staging per hosted agent. This is an admission estimate, not a hard per-agent memory cap or a production capacity measurement. If no slot fits, unscheduled checks become UNKNOWN and priorities are skipped when headroom is still insufficient. Each concurrent invocation keeps separate private credential files and process cleanup.

The hosted analyzer remains configured at 1 vCPU / 8 GiB and the collector at 4 vCPU / 16 GiB. Overlapping network-bound work aims to shorten billed task duration. Actual savings and safe lower sizing require representative live scan memory/CPU measurements; parallelism does not reduce model tokens or total cloud API calls by itself.

## Compact priorities input

### Network review

The Network agent explains each VPC/VNet/network and its subnet tiers with network/tier headings and short bullets, using up to 12000 characters when needed. It describes attached workloads, likely purpose, routing, tier boundaries and the configuration supporting that interpretation; equivalent default networks are grouped together. It suggests concrete segmentation, firewall/SG/NSG/ACL, routing, peering, private-endpoint and Kubernetes policy improvements where supported. It must preserve required connectivity and describe dependency checks and safe verification. Unknown business intent produces MANUAL advice; missing configuration produces UNKNOWN; FAIL requires evidence of the claimed configuration weakness. An allow declaration alone does not establish reachable traffic.

Its `topology.json` contains every collected boundary plus complete node/relationship group catalogs with explicit example samples. Its separate `platform.json` covers network rule candidates and existing network signals; `context.sqlite` holds their original records and scoped native network properties. Workload data is projected to network fields, omitting user data, environment variables and unrelated configuration. Secret-bearing VPN/authentication fields are excluded. IAM, privilege-escalation and least-privilege records are not supplied. The YAML INPUTS section documents every input and the bounded local reader, including `list ... --all` for structural records.

Network output has `explanation` and `findings`; it does not request or display a limitations section. Decision-changing uncertainty belongs in the affected finding. Each proposed finding has title, description, rationale, affected resource, severity/status, structured evidence, remediation and verification. The backend validates references and assigns stable IDs, network category, provider/scope/service and explicit `ai_network_review` provenance, without inventing compliance mappings. New findings appear in the ordinary Findings UI/report and on the Network Findings page below Network Map, using the same findings table and detail drawer as other security findings. The findings table appears first, followed by an architecture outline organized by network and subnet tier; older dense summaries are split into readable blocks without changing their wording. The table shows severity, finding/evidence preview, service, affected asset, provider/scope and status, with search, severity/status filters, sorting and 25-row pages across the complete result set (up to 100). The drawer retains the complete description, rationale, evidence, remediation and verification. Evidence previews use 1–3 short natural-language lines explaining the specific weak configuration. Empty or whitespace-only finding text is rejected, and display names/native IDs come from the referenced inventory rather than the model; original scanner observations remain intact. Priorities receives the final network explanation, review status and these findings, including MANUAL/UNKNOWN recommendations whose assumptions it must preserve. A failed network review records unavailability and does not discard the other reviews or block priorities from using available evidence. The same concurrency, memory admission, timeout, credential-file and process-cleanup rules apply.

### Prioritization brief

For Hardening and Exposure, priorities receives only original FAIL checks whose final rechecker verdict is FAIL. PASS, UNKNOWN, DENIED, MANUAL, NOT_APPLICABLE, EMPTY and unreviewed checks are excluded before writing the decision brief and the underlying lookup database. Other security areas retain their own uncertainty states. Full original scanner findings and all review results remain available in the platform report and UI.

`briefing.py` stores original records in a mode-0600 local SQLite file. `decision_brief.py` creates one complete decision catalog in `platform.json`, replacing the former four-previews-per-domain approach. Every decision group is represented across five sections: findings, least privilege, privilege escalation, IAM and network. The agent compares these sections before fetching original evidence. Large sections can be paginated through the same local helper, without omitting candidates.

The brief has `version`, `scan`, `review_counts`, `counts`, `coverage`, `sections` and `reading_notes`. Every case has `id`, `signal`, `state`, `severity`, `count`, `unit`, `facts`, `example` and `related`. The priorities YAML INPUTS section explains each field and each section's facts, the distinction between case IDs and output references, the credential JSON, and all lookup response shapes. The action output remains the existing seven-field schema.

Repeated findings share a control/verdict group; Hardening and Exposure groups contain only finally confirmed FAILs. Least-privilege suggestions stay separate by kind, provider source and confidence. Escalation edges preserve technique/confidence combinations and show source/target counts, aggregate size, conditions and mitigation samples. IAM cases summarize declared-grant risk, severity counts and restrictions without claiming effective access. Network grouping preserves rule type, ports, protocol, source and reachability; unsupported rule shapes remain distinct. Risk-marked IAM edges and network nodes are also represented. Samples and differing member details are explicit, with complete retained source records still accessible.

`related` precomputes counts of cases in other sections sharing exact resource/identity references within two reference hops. This lets the agent spot a control associated with exposure, escalation and excessive access without first traversing the full graphs. It does not infer reachability, federation or an attack chain. Ambiguous references remain unjoined. `example` points directly to an original record; `members` retrieves the underlying group and `related_cases` retrieves the cases counted in `related`.

The read-only `context.py` helper includes `focus decision_SECTION CASE_ID --limit 2`. This returns a highest-severity member and a member with broad cross-domain reference context, original decision facts and concrete related-case witnesses. Least-privilege suggestions are filtered to that case’s confidence/kind/source; unrelated suggestions on the same principal are excluded. Escalation outcomes retain inferred/catalog labeling, and native IAM permission samples preserve field semantics such as Action versus NotAction. Correlations use reference-bearing fields and qualified identifiers, rather than arbitrary scalar values matching resource names.

The read-only `context.py` helper returns bounded JSON with `total`, `offset`, `next_offset` and `items`. `get --path` selects original nested fields using JSON Pointer. Long strings support explicit character windows. The helper reduces page size or returns guidance rather than silently truncating evidence. No platform API or administrator token is needed. The agent expands only proposed leading actions, materially differing members and uncertain relationships, rather than reading all raw inventory and topology.

Start with `python context.py focus decision_findings CASE_ID --limit 2`. Fallback examples: `python context.py members decision_findings CASE_ID --limit 4`, `python context.py related_cases decision_findings CASE_ID --limit 4`, and `python context.py get findings FINDING_ID --path /finding/evidence`. Case IDs are lookup keys; action references use original findings or platform resource IDs.

A separate local synthetic size check condensed 5,000 findings into 100 complete cases (38,961 bytes) in approximately 0.22 seconds. The smaller 60-finding fixture is approximately 1.3 MB as a full input and roughly 5 KB as a complete six-case brief. This is a synthetic initial-reading comparison, not a live quality, token-cost or deployed-performance result. [Example decision brief](example-priorities-input.json).

## Runtime dependency

CSPM pins the public Chack source to `7e258d0602b9aa065bfa2d06aa53be5fe525531f`. The adjacent Chack checkout contains additional uncommitted work; it was not copied or changed. The pinned package was installed and its actual configuration constructors were checked locally.

## Chack syntax used

Each agent has its task instructions, good/bad examples, model/backend, limits, tools and schema reference in a native Chack YAML. For example:

```yaml
system_prompt: |
  Review only the failed Hardening checks in findings.json.
  Each item includes its evidence and supporting_resources for that check.
user_prompt: |
  {access_instructions}

  Review the supplied task files and return only the requested JSON.
agent:
  primary: OPENAI_BEST_QUALITY
  provider: codex
  api_key_type: codex
  main_action: cspm
  sub_action: hardening
  output_schema_file: ../reviews.schema.json
```

The runner uses Chack's `load_config()` and passes generated access guidance through `prompt_variables_override={"access_instructions": ...}` to `Chack.run()`. The instructions describe only the entries actually in that invocation's credential file: an AWS agent receives only AWS session guidance, and an Azure agent receives guidance only for the audiences present. No cloud credential values are interpolated into prompts. If no access is supplied, the agent receives an explicit evidence-only instruction instead of credential tutorials.

Current Chack YAML uses a flat `agent` section; legacy top-level `model` and `session` sections are rejected. The selected AI credential, model and thinking effort are injected into the loaded configuration by the runner from its private file; AI credentials are not cloud credentials and are not stored in YAML. The runner serializes native OpenRouter SDK structured results as JSON before applying the same output and reference validation used for CLI backends.

## Provider, model and thinking selection

Settings supports OpenAI API keys, Codex sign-in, Anthropic API keys, Claude Code subscription tokens (`claude setup-token`), and OpenRouter API keys. The user enters an exact model ID and selects a thinking effort. CSPM validates the combination against the supplied credential before encrypting and saving it. Every provider sends a small test inference with tool support and the selected thinking effort; Codex and Claude also check authenticated model capabilities. Provider error bodies and credentials are never returned to the browser.

`GET /api/ai/configuration` returns availability, the user's own nonsecret selection, and whether a credential is saved. `POST` accepts `provider`, `model`, `thinking` and optional `credential`; omitting the credential retains the same user's saved credential only when the provider is unchanged. Codex uses the encrypted personal sign-in instead. `POST /api/ai/configuration/validate` explicitly revalidates the saved selection after repair. `DELETE` removes the custom selection; hosted deployments validate HackTricks AI before accepting this explicit switch. These routes require a user account and operate on that user, including from a shared workspace. API keys remain read-only.

All Hardening, Exposure, Network and Priorities agents, including retries and child roles, receive the same resolved selection. OpenAI keys and Codex sign-in use Chack's **codex** backend; Anthropic keys/tokens use **claude**; OpenRouter keys use **openrouter**. Explicit model and thinking choices override stage YAML defaults. Invalid efforts are rejected rather than clamped. Local Claude execution requires the Claude Code CLI; the container images pin version 2.1.304 alongside Codex 0.147.0.

On the hosted service, **HackTricks AI** is used when no personal configuration is selected. The platform's credential, model and thinking are never included in the settings response. A failed personal or platform validation stops AI without switching credentials. Settings displays the sanitized error and its navigation entry shows a warning until an explicit successful save, revalidation or validated default switch. Validation runs before accepting AI-enabled scans/schedules, before hosted workflow dispatch, before every local or Fargate agent launch, and inside the runner before constructing Chack (including repair attempts). Queued work rechecks current saved settings; changed settings stop stale launches. A failure stops later launches in the same pool. Deterministic scan results remain available when an already-running scan cannot start AI. New local Codex sign-ins require explicit model and thinking choices before AI scans are enabled. Existing local Codex/YAML installations keep their previous behavior until a custom selection is saved.

The trusted hosted relay supports fixed, provider-specific Responses or Messages endpoints; real credentials remain in the relay container. The agent receives a task-local capability and its selected model/effort. It cannot change provider, model or effort through the relay, follow provider redirects, or use the relay as a general proxy. OpenRouter requests require providers to support the selected parameters.

Validation references: [OpenAI reasoning](https://developers.openai.com/api/docs/guides/reasoning), [Claude model capabilities](https://platform.claude.com/docs/en/api/http/models/retrieve), and [OpenRouter parameter requirements](https://openrouter.ai/docs/guides/routing/provider-selection#requiring-providers-to-support-all-parameters).

## Personal sign-in and platform default

Settings starts a device-code login, displays the fixed OpenAI verification link and code, and polls until sign-in finishes. Login state and tokens are encrypted; neither access nor refresh tokens return to the browser. State is durable in SQLite or DynamoDB, so requests do not need the same API process. Conditional writes coordinate polling, disconnects and refresh-token rotation.

A scan records its authenticated initiating user server-side. A validated personal AI selection overrides the platform default for that user's scans and schedules. Shared-workspace schedules retain their initiating user; AI refuses to use that user's connection after their write/admin membership is removed. An expired or broken personal connection blocks AI in both hosted and local deployments until the user explicitly validates a working configuration. Disconnecting personal Codex auth makes any selection using that auth unavailable.

The device flow mirrors `codex-rs/login/src/device_code_auth.rs` and the fixed Codex client ID in the local Codex source. OpenAI documents device sign-in and its prerequisite in [Codex authentication](https://learn.chatgpt.com/docs/auth#login-on-headless-devices). This protocol is version-sensitive; a real end-to-end sign-in remains a live acceptance check.

Platform authentication uses `CODEX_ACCESS_TOKEN` or an explicitly configured `CODEX_TOKEN_SECRET_ARN`. A secret contains a plain access token or JSON with an `access_token` field. The runtime fetches it with `secretsmanager:GetSecretValue`; grant access to that ARN only, plus `kms:Decrypt` on its key if needed. Token refresh/publication belongs to the operator. CSPM has no built-in table, login, secret name or account lookup. A validated personal Settings selection remains available and takes precedence. Local installs never query AWS for a token without a configured secret ARN. Supply an AWS runtime identity separately when using a secret locally; Compose does not mount host AWS credentials automatically.

Local AI launch requires usable access to the selected provider. The launch/schedule checkbox is disabled and unchecked until `/api/ai/codex` reports access available. API requests in both deployment modes with AI enabled (including the default when omitted) return HTTP 409 before enqueueing or saving an AI schedule if AI configuration resolution or personal refresh fails. Requests with `ai_enabled: false` remain available. Schedules recheck access before dispatching each occurrence. Compose passes the configured token to the API, scheduler/collector and analyzer so they use the same configuration.

## Cloud credential handoff

Collection captures the successfully resolved authentication context, after the existing provider-specific authentication logic. It does not reconstruct authentication independently or select another credential chain.

| Provider | What the temporary JSON file contains |
| --- | --- |
| AWS | No AWS session is sent to an AI agent. The agents review the captured scan evidence without live AWS API access. |
| GCP | The OAuth bearer token used by the collector, with its API audience and expiration when available. This covers ADC, service accounts, gcloud, federation, impersonation, metadata and explicit tokens after the collector resolves them. Source service-account private keys and refresh configuration are not exported. |
| Azure | Separate resolved bearer entries for ARM, Microsoft Graph, Vault, Storage and other audiences actually accessed by collection. Client secrets, certificate private keys, managed-identity metadata and source federation tokens are not exported. Missing audiences are explicitly unavailable. |
| Kubernetes | A self-contained kubeconfig with the resolved API server, CA/TLS server name and current authentication. Exec helpers and source file paths are replaced with the current token or embedded client-certificate material. |

The version-2 file includes provider, credential-context scope, format, capture time and expiry when known, plus explicit `target_scopes`. One GCP token can list many project, folder or organization scopes; separate transport identities remain separate even with the same audience. GCP capture happens at the final API transport, so impersonation source tokens are not exported. Azure entries retain tenant, audience, subscription IDs and captured API origins, including resource-specific Vault and Storage endpoints. Kubernetes entries retain cluster ID and assigned namespaces, with a separate client per cluster. Refreshes update the token without dropping previously captured targets. Lists are not truncated. Quota/billing projects remain distinct from GCP target projects. The per-invocation prompt explains only the credential formats and API audiences actually supplied to that agent and how to match those accesses. Missing or expired access is a limitation, never permission to discover another chain.

The agent handoff accepts many credential contexts and targets. The existing Kubernetes connector still selects one cluster per scan, with multiple namespaces; this change does not add multi-cluster scan orchestration. Ambiguous namespace-only findings cannot select a credential when multiple clusters are supplied.

There is no universal way to mint a newly expiring credential for arbitrary supplied Kubernetes client certificates or opaque provider tokens. Kubernetes certificate authentication retains its existing certificate lifetime; it is materialized in a temporary private file. Unknown expiry is recorded as null. The implementation guarantees an ephemeral file, not a newly shortened provider lifetime for every authentication method. AWS credentials are not exported to AI agents.

Captured access is encrypted at rest with an AI-only envelope key. The analyzer still cannot decrypt source connector credentials, read the platform GCP service-account secret or assume customer roles. Each agent runs in a new process with a clean environment, private HOME/CODEX_HOME, a mode-0700 directory and mode-0600 credential files. Credentials do not enter prompts, command arguments or inherited cloud environment variables. Output is schema-checked and credential values are redacted before publication. Cancellation/timeouts kill the child process tree and remove temporary files.

Chack's pinned Codex backend invokes the CLI with sandbox bypass. A clean environment and file permissions prevent accidental handoff; they are not an OS sandbox against a malicious same-UID process. Do not interpret the prompt's read-only instruction as an IAM permission boundary: live calls for other providers retain the effective rights of the supplied sessions. Existing scan accounts should use the documented read-only scan roles. The integration does not automatically create new roles or change permissions.

## Local setup and infrastructure

Install `.[ai]` for native use and install the Codex CLI. Dockerfiles install pinned `@openai/codex@0.147.0` and the pinned Chack dependency. Sign in through Settings, launch an AI-enabled scan, and open Top 15 Actions or Network Findings. Both navigation entries appear when personal AI access or HackTricks AI is available.

Compose now gives the analyzer network access for Codex and cloud verification. It mounts only the separate AI-key volume, not the source connector-key volume. The API initializes the shared AI key before workers start. `PEASO_AI_TIMEOUT_SECONDS` defaults to 300. The scan's existing deadline remains authoritative.

Hosted Terraform adds an independent KMS key and Secrets Manager secret for AI envelopes, wires the configured runtime token secret and keeps the connector-key deny for the analyzer. The release source-hash contract and environment checks were updated explicitly for these additions; historical plans/approval artifacts were not modified. No Terraform plan/apply or workflow dispatch was performed.

## Verification

- AI backend tests cover schemas, exact duplicate handling, complete review coverage, cross-account references, rank/dependency validation, opt-out, partial failures, personal-auth isolation, encryption, conditional writes, rejection of AWS session handoff, clean subprocess environments, redaction and tenant-scoped result pagination.
- Credential scale tests cover one GCP token over 50 projects, 30 separate GCP identities, two Azure tenants with separate API audiences across 50 subscriptions, and 20 Kubernetes contexts with 30 namespaces each. Tests exercise GCP/Azure capture, Kubernetes SDK loading and the private JSON handoff.
- Latest credential/collector regression run: 316 passed, with `test_native_service_coverage_and_configuration_fixture` excluded. That fixture fails on `log_secret_sample` returning `log_sample_not_enabled`; its transport does not exercise the changed credential capture.
- Existing scan/API/cloud-collector tests passed: 422 tests. Worker/calendar/large-response tests passed separately: 60 tests.
- Release guard tests passed: 58 tests and 197 subtests.
- Chromium checks passed: scan toggle and schedule default, personal sign-in/cancel, action table and unresolved exposure.
- Frontend production build passed. Existing large-bundle warning remains.
- Terraform 1.14.3 initialization and validation passed in a temporary directory with the backend disabled. No cloud credentials were used. The system Terraform is older than this repository's requirement.
- Pinned Chack dependency installation and typed configuration constructor checks passed without invoking an agent.

Live acceptance still needs a real personal device login, the hosted shared-token read under the deployed analyzer role, a Docker image build (the local daemon is not running), and one AI-enabled scan per provider including multi-account AWS and Kubernetes certificate auth. The UI screenshot and JSON example use mocked evidence; they are not live security conclusions.


## Reviewing AI/engine disagreements

Top 15 Actions contains only the prioritized actions and their plans. AI verification belongs in Hardening and Exposure. AI output alone is not proof that an evaluator is wrong: confirm the native facts and intended control semantics, add positive and negative regression cases, and preserve genuine failures.

An operator can re-evaluate an existing completed scan from its retained snapshot with `scripts/peaso_reconcile_scan.py`. It uses the normal `PEASO_STORAGE` settings and defaults to a dry-run. Specify the tenant, scan ID, exact expected report reference and source version. Optional adjudications are explicit reviewed decisions bound to existing category/finding IDs. `--apply` publishes a new report and changes the report pointer only if the completed scan still references the expected report. The prior artifacts and original snapshot remain intact; no target-account collection or AI calls are made. Hosted storage still uses its configured AWS APIs.

Reviewers receive the same concise natural-language observation shown with a finding, its exact stored pass/fail criteria, and its original native evidence. Their prompts require affirmative proof for PASS, preserve any-versus-all semantics, separate configuration checks from exploitation, and identify live state changes without inventing engine defects. Explanations use 1–3 short sentences. Hosted release acceptance includes a real-model counterexample: a single TCP 443 rule open to everyone on a customer-managed interface must remain FAIL.


The Network agent also receives `exposure.json`, a compact catalog of unresolved Exposure issues (finding/check IDs, titles, affected resources, scopes, statuses and available evidence summaries). It excludes full policies and unrelated workload configuration. The agent must avoid repeating the same issue and fix; a resource may still have a distinct internal segmentation issue. Existing Exposure verdicts remain owned by their original checks/reviews.
