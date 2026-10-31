# HTTP API

The server is a FastAPI app (`peaso/server/app.py`, `create_app`). The same app runs locally
(`python -m peaso.server`), in Docker, and on AWS Lambda through Mangum
(`peaso/server/lambda_handler.py`). FastAPI's interactive docs are available at `/docs` when
the app runs.

All routes are under `/api`. Request bodies are strict: unknown fields are rejected with `422`,
and validation errors never echo the submitted values (they may contain credentials).

## Authentication

Every request except `/api/health` needs `Authorization: Bearer <credential>`. The credential
can be:

| Credential | Mode | Notes |
| --- | --- | --- |
| Local token | `PEASO_AUTH_MODE=local` | From `PEASO_LOCAL_TOKEN`, or generated into `<identity dir>/local.token` |
| Cognito ID/access token | `PEASO_AUTH_MODE=cognito` | Verified against `PEASO_COGNITO_ISSUER` and `PEASO_COGNITO_CLIENT_ID`; a `__Secure-ht_refresh` cookie can also authenticate |
| API key | both | Format `hacktricks_cspm_<32 hex>_<43 chars>`; **read-only** |

API keys:

- Create with `POST /api/api-keys` (`name`, optional `expires_at`), list with
  `GET /api/api-keys`, revoke with `DELETE /api/api-keys/{key_id}`.
- At most 20 unrevoked keys per account. Only a hash is stored; the key is shown once.
- Keys only work for `GET`/`HEAD`. Any other method returns `403`. Keys cannot manage keys or
  select a shared workspace.

Cookie-authenticated writes must come from an allowed origin (`PEASO_ALLOWED_ORIGINS`).

## Workspaces

Each account has a personal workspace. Shared workspaces (`ws_<32 hex>`) are selected with the
`x-workspace-id` header. Roles:

| Role | Can |
| --- | --- |
| `read` | Read everything, run reachability queries |
| `write` | Also create connectors, scans and schedules |
| `admin` | Also manage members and delete workspace data |

Routes: `GET/POST /api/workspaces`, `GET /api/workspaces/{id}/people`,
`POST /api/workspaces/{id}/invitations`, `DELETE /api/workspaces/{id}/invitations/{member_id}`,
`GET /api/workspaces/invitations`, `POST /api/workspaces/invitations/{id}/accept|decline`,
`PATCH|DELETE /api/workspaces/{id}/members/{member_id}`.

`DELETE /api/workspace-data?confirmation=DELETE` (admin only) deletes the workspace's data.

## Connectors

A connector stores a provider, auth object, scopes and options. Credentials are encrypted at rest.

| Method and path | Purpose |
| --- | --- |
| `POST /api/connectors/prepare` | Prepare server-side values (for example the AWS External ID) |
| `POST /api/connectors/check-access` | Test the reads; returns a `check_token` and any warnings |
| `POST /api/connectors` | Create (`name`, `provider`, `auth`, `scopes`, `options`, `check_token`, `acknowledge_access_warnings`) |
| `GET /api/connectors`, `GET /api/connectors/{id}` | List / read (no secrets returned) |
| `PATCH /api/connectors/{id}` | Update |
| `DELETE /api/connectors/{id}` | Delete |

When `PEASO_REQUIRE_CONNECTOR_ACCESS_CHECK` is true (the Docker default), create and update need
a valid `check_token` from a matching access check.

## Scans

`POST /api/scans` body (send an `Idempotency-Key` header to make retries safe):

```json
{
  "connector_id": "…",
  "categories": ["hardening", "exposure", "network"],
  "checks": [],
  "frameworks": [],
  "content_checks": [],
  "leaks_enabled": true,
  "images_enabled": false,
  "ai_enabled": true,
  "ai_network_enabled": true,
  "ai_priorities_enabled": true
}
```

| Method and path | Purpose |
| --- | --- |
| `GET /api/scans`, `GET /api/scans/{id}` | List / status and progress |
| `POST /api/scans/{id}/cancel`, `POST /api/scans/{id}/resume`, `DELETE /api/scans/{id}` | Control |
| `GET /api/scans/{id}/summary` | Counts and headline data |
| `GET /api/scans/{id}/report` | Full report |
| `GET /api/scans/{id}/findings` | Paged findings; filters `categories`, `framework`, `severity`, `service`, `status`, `search`, `finding_type`; `group_by`, `sort_by`, `offset`, `limit` (≤ 500) |
| `GET /api/scans/{id}/finding-groups/{group}` | One finding group |
| `GET /api/scans/{id}/findings/{finding_id}` | Finding detail, including `secret_evidence` for secret findings |
| `GET /api/scans/{id}/resources`, `/resources/{resource_id}` | Inventory |
| `GET /api/scans/{id}/coverage` | What was collected, denied or missing |
| `GET /api/scans/{id}/least-privilege` (+ `/grants`, `/principals/{id}`) | Least-privilege views |
| `GET /api/scans/{id}/privesc/admins|paths|broad|principals/{id}` | Privesc queries |
| `GET /api/scans/{id}/graphs/...` | Graphs (see [network-and-exposure.md](network-and-exposure.md)) |
| `POST /api/scans/{id}/reachability` (+ `/batch`, `/matrix`, `/grid`) | Selected-flow reachability |
| `GET /api/scans/{id}/image-findings` (+ `/{finding_id}/assets`) | Image CVEs |
| `GET /api/scans/{id}/ai` | AI review status and results |

Finding detail responses that include secret values are sent with
`Cache-Control: private, no-store`.

## Schedules

`POST /api/schedules` takes the scan fields plus either `interval_hours` (1 to 8760, default 168)
or `rules` (up to 20 of `{frequency: daily|weekly|monthly, time: "HH:MM", weekdays, day_of_month}`),
a `timezone` (default `UTC`), `enabled` and optional `next_run_at`. Also `GET`, `PATCH` and
`DELETE /api/schedules/{id}`. The scheduler (`scheduler_handler.py`) starts due scans.

## Other routes

| Path | Purpose |
| --- | --- |
| `GET /api/health` | Liveness, auth mode, and `PEASO_SOURCE_URL` / `PEASO_SOURCE_VERSION` if set |
| `GET /api/me` | Current identity and plan |
| `GET /api/catalog`, `/api/catalog/frameworks`, `/api/catalog/checks/{id}` | Catalog |
| `POST /api/attack-analysis/check-access`, `/run` | Attack detection (see [attack-detection.md](attack-detection.md)) |
| `/api/ai/configuration` (+ `/validate`), `/api/ai/preferences`, `/api/ai/codex` (+ `/login`, `/login/poll`) | AI settings (see [ai-review.md](ai-review.md)) |

## Example

```bash
TOKEN=$(docker compose exec -T api cat /var/lib/peaso/identity/local.token)
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/api/scans
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:8000/api/scans/$SCAN/findings?status=FAIL&severity=high&limit=100"
```

## Best practices

- Use API keys for dashboards and automation that only read; keep write access to signed-in users.
- Set expiry dates on API keys and revoke unused ones.
- Always send an `Idempotency-Key` when creating scans from scripts.
- Page through findings with `offset`/`limit` instead of downloading the full report repeatedly.
- Keep `PEASO_REQUIRE_CONNECTOR_ACCESS_CHECK` enabled so broken connectors are caught before scans.
