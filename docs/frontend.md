# Web frontend

The web app in `frontend/` is a React 19 single-page app built with Vite and TypeScript. It talks
only to the PEASO API under `/api` and shows results progressively: native results appear as
soon as each part of the scan is ready, and AI sections fill in later.

Main libraries: TanStack Query (data fetching), TanStack Table and Virtual (large tables),
`@xyflow/react` with `elkjs` (graph layout, in a web worker), and Playwright for end-to-end tests.

## Pages

| Group | Page | What it shows |
| --- | --- | --- |
| Setup | Dashboard | Scan summary, counts by status and category, recent scans |
| | Connectors | Add and edit provider connectors, auth guides, access check |
| | Scans | Start, cancel, resume and schedule scans; scan list |
| Security insights | Top 15 Actions (AI) | Prioritized actions from the AI review |
| | Hardening & Compliance | Native hardening findings and framework views |
| | Exposure | Internet exposure and external principal findings |
| | Least Privilege | Principals, grants and unused permissions |
| | Privilege Escalation Map | Privesc graph, admin reach and paths |
| | Network Map | Network graph and reachability queries |
| | Network Architecture (AI) | AI review of the network layout |
| | Leaks | Secret findings from content scans |
| | Images CVEs | Container image vulnerability findings |
| | Attack Detection | Audit-log detections |
| Account | Settings | AI configuration, Codex sign-in, API keys, workspaces |
| | Help | In-app help |

Before sign-in, the app shows a built-in demo data set so you can look around without a server.
Each finding opens a **finding inspector** with the observed evidence, affected resources and,
for secret findings, the clear-text value (only for authorized users).

## Authentication in the browser

- **Local mode**: paste the local token. It is kept in `sessionStorage` (cleared when the tab
  closes) and sent as `Authorization: Bearer <token>`.
- **Hosted mode**: sign in with Cognito; a secure refresh cookie keeps the session.
- The selected workspace is sent in the `x-workspace-id` header.

## Development

```bash
cd frontend
npm ci
npm run dev          # Vite on http://127.0.0.1:5173, proxies /api to PEASO_API_ORIGIN
npm run typecheck    # TypeScript only
npm run build        # tsc -b && vite build -> frontend/dist
npm run preview      # serve the built app
npm run test:e2e     # Playwright tests in frontend/tests
```

Environment variables:

| Variable | Default | Use |
| --- | --- | --- |
| `PEASO_UI_PORT` | `5173` | Vite dev server port |
| `PEASO_API_ORIGIN` | `http://127.0.0.1:8000` | Where the dev server proxies `/api` |
| `PEASO_UI_URL` | `http://127.0.0.1:5173` | Base URL for Playwright |

Run the API (`python -m peaso.server`) and workers alongside the dev server, and add
`http://127.0.0.1:5173` to `PEASO_ALLOWED_ORIGINS` if you call the API cross-origin.

In production the built `dist/` is either copied into `peaso/frontend_dist` (served by the API
on the same origin, as in the Docker image) or uploaded to the S3 bucket behind CloudFront
(hosted deployment).

## Tests

Playwright tests live in `frontend/tests` and run in Chromium. Most use mocked API responses, so
they need no backend. Specs that need a live server are skipped unless their variables (for
example `PEASO_LIVE_TOKEN`) are set. CI runs them with `PEASO_API_ORIGIN=http://127.0.0.1:9` to
make sure no test depends on a real API.

```bash
npx playwright install --with-deps chromium
npx playwright test --reporter=list
```

## Best practices

- Fetch through the shared API helpers so the token and workspace header are always set.
- Keep large lists virtualized and use server paging (`offset`/`limit`) for findings and graphs.
- Never render secret values outside the finding inspector, and never cache them in storage.
- Show native results immediately; never block a page on AI.
- Mock the API in Playwright tests unless the test is explicitly about live behaviour.
