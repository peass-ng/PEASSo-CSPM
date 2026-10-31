# Configuration reference

PEASO CSPM is configured with environment variables (server, workers, deployment) and with
per-connector options (collection). Collection options are described in
[collectors.md](collectors.md); this page lists the environment variables.

For Docker Compose, put values in `.env` (copy from `.env.example`, keep it at mode `600`).

## Server

| Variable | Default | Meaning |
| --- | --- | --- |
| `PEASO_BIND` | `127.0.0.1` | Address for `python -m peaso.server` |
| `PEASO_PORT` | `8000` | Port for the server (and the published Docker port) |
| `PEASO_AUTH_MODE` | `local` | `local` (single token) or `cognito` |
| `PEASO_LOCAL_TOKEN` | generated | Local bearer token; if empty, one is generated into `<identity dir>/local.token` |
| `PEASO_ALLOWED_ORIGINS` | localhost/127.0.0.1 on ports 8000 and 5173 | Comma-separated CORS origins |
| `PEASO_COGNITO_ISSUER`, `PEASO_COGNITO_CLIENT_ID` | — | Cognito user pool issuer URL and app client ID |
| `PEASO_SCAN_TIMEOUT_SECONDS` | `900` | Scan time budget |
| `PEASO_REQUIRE_CONNECTOR_ACCESS_CHECK` | `false` (`true` in Docker Compose) | Require a passing access check before saving a connector |
| `PEASO_SOURCE_URL`, `PEASO_SOURCE_VERSION` | — | Shown by `/api/health` |

## Storage and encryption

| Variable | Default | Meaning |
| --- | --- | --- |
| `PEASO_STATE_DIR` | `.peaso/state` | SQLite database and artifact files (local mode) |
| `PEASO_IDENTITY_DIR` | `.peaso/identity` | Local token and generated encryption keys |
| `PEASO_STORAGE` | `sqlite` | `sqlite` or `dynamodb` |
| `PEASO_DYNAMODB_TABLE` | — | DynamoDB table (dynamodb mode) |
| `PEASO_ARTIFACT_BUCKET`, `PEASO_ARTIFACT_KMS_KEY` | — | S3 artifact bucket and KMS key (dynamodb mode) |
| `PEASO_WORKFLOW_ARN` | — | Step Functions state machine; when unset, workers poll the store |
| `PEASO_ENCRYPTION_KEY` | — | Fernet key for connector credentials |
| `PEASO_CREDENTIAL_SECRET_ARN` | — | Secrets Manager secret holding that key (required in dynamodb mode if no key is set) |

Without either encryption variable in local mode, a key is generated at
`<identity dir>/credentials.key`. Back up the identity directory together with the state
directory; one without the other cannot decrypt saved connectors.

## AI

| Variable | Default | Meaning |
| --- | --- | --- |
| `CODEX_ACCESS_TOKEN` | — | Platform Codex token for AI review |
| `CODEX_TOKEN_SECRET_ARN` | — | Secrets Manager secret with the token (plain or JSON with `access_token`) |
| `PEASO_AI_ENCRYPTION_KEY`, `PEASO_AI_CREDENTIAL_SECRET_ARN` | — | Separate key for AI credentials; otherwise a key file under `<identity dir>/ai/` |
| `PEASO_AI_ISOLATION_LAUNCHER` | — | Absolute path to the isolation launcher (local runtime) |
| `PEASO_AI_RUNTIME` | — | Set to `fargate` for the hosted AI runtime |
| `PEASO_AI_FARGATE_CLUSTER`, `_TASK_DEFINITION`, `_SUBNETS`, `_SECURITY_GROUPS`, `_BUCKET` | — | Fargate AI runtime settings |
| `PEASO_AI_TIMEOUT_SECONDS` | `300` local, `600` Fargate | AI time budget per scan |
| `PEASO_AI_MAX_CONCURRENCY` | `2` | Parallel AI reviews per analyzer |

## AWS hosted onboarding and platform identities

| Variable | Meaning |
| --- | --- |
| `PEASO_AWS_COLLECTOR_ROLE_ARN` | The role customers trust; its account is treated as a platform account |
| `PEASO_PLATFORM_ACCOUNT_IDS` | Comma-separated platform accounts customers cannot register |
| `PEASO_PUBLIC_CUSTOMER_ROLE_TEMPLATE_URL` | Optional public quick-create URL for the customer role template |
| `PEASO_GCP_PLATFORM_SA_SECRET_ARN` | Secret with the GCP platform service account key (`platform-service-account` method) |
| `PEASO_GCP_PLATFORM_PROJECT`, `PEASO_GCP_PLATFORM_EMAIL` | GCP platform project and service account email |

## Cost estimation and billing (hosted)

| Variable | Default | Meaning |
| --- | --- | --- |
| `PEASO_TASK_VCPU`, `PEASO_TASK_MEMORY_GIB` | `1`, `6` | Default task size for cost estimates |
| `PEASO_COLLECTOR_VCPU`, `PEASO_COLLECTOR_MEMORY_GIB`, `PEASO_ANALYZER_VCPU`, `PEASO_ANALYZER_MEMORY_GIB` | 4 / 16 and 1 / 8 | Per-stage sizes for cost estimates |
| `PEASO_VCPU_SECOND_USD`, `PEASO_MEMORY_GIB_SECOND_USD` | Fargate list prices | Rates used for estimates |
| `PEASO_STRIPE_SECRET_ARN`, `PEASO_STRIPE_PRICE_ID` | — | Billing integration |

## Attack detection rules

| Variable | Meaning |
| --- | --- |
| `HACKTRICKS_CSPM_RULES_GITHUB_REPO`, `HACKTRICKS_CSPM_RULES_GITHUB_REF` | Alternate rule repository and ref (pinned mode) |
| `HACKTRICKS_CSPM_RULES_PACK_SHA256` | Expected digest for the alternate rule pack |
| `HACKTRICKS_CSPM_RULES_DIR` | Local rule directory (local auth mode only) |

## Frontend development

| Variable | Default | Meaning |
| --- | --- | --- |
| `PEASO_UI_PORT` | `5173` | Vite dev server port |
| `PEASO_API_ORIGIN` | `http://127.0.0.1:8000` | API target of the dev proxy |
| `PEASO_UI_URL` | `http://127.0.0.1:5173` | Playwright base URL |

## Best practices

- Never put secrets in `PEASO_ALLOWED_ORIGINS`, URLs or command lines; use `.env` or Secrets Manager.
- In hosted mode, always set `PEASO_CREDENTIAL_SECRET_ARN` and `PEASO_AI_CREDENTIAL_SECRET_ARN` to different secrets.
- Back up state and identity directories together, and protect the identity directory like a password store.
- Keep `PEASO_BIND` on loopback unless the server is behind an authenticating proxy.
- Turn on `PEASO_REQUIRE_CONNECTOR_ACCESS_CHECK` outside development.
