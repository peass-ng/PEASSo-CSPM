# Testing

The project has a Python test suite in `tests/` (pytest) and browser tests in `frontend/tests`
(Playwright). CI runs both on every change in `.github/workflows/tests.yml`.

## What tests should look like

- **Test behaviour, not text.** A test should prove what the code does with realistic input:
  a check returns `FAIL` for a bad setting, `PASS` for a good one, and `UNKNOWN` when a fact is
  missing or malformed. Do not add tests that only pin file hashes, exact strings, names or
  counts; they break on every harmless change and catch no bugs.
- **No live cloud calls.** Use stubbed SDK clients, injected transports (`transport=` for Azure,
  `api=` for Kubernetes), saved snapshots and the fixtures in `peaso/checks/fixtures.py`.
- **Fast and independent.** Tests must not depend on order or wall-clock timing and must reset
  any per-process state they touch, because CI runs them in parallel.

## Running Python tests

```bash
pip install -e '.[test,cloud,secrets,ai]'
pip install pytest-xdist

python -m pytest -q                                   # whole suite
python -m pytest -q tests/test_peaso_native_storage_compute.py   # one file
python -m pytest -q -n auto --dist loadfile           # in parallel
```

Some tests use external tools when available and are skipped otherwise:

| Tool or input | Variable |
| --- | --- |
| TruffleHog and Kingfisher | on `PATH` / installed package |
| Trivy | `PEASO_TEST_TRIVY_CLI`, `PEASO_TEST_TRIVY_DB` |
| Codex and Claude CLIs (AI relay tests) | `PEASO_TEST_CODEX_BIN`, `PEASO_TEST_CLAUDE_BIN` |
| Terraform (infrastructure tests) | `PEASO_TERRAFORM` |
| HackTricks Cloud checkout (privesc source checks) | `HACKTRICKS_CLOUD_ROOT`, `PEASO_HACKTRICKS_ROOT` |
| Benchmarks | `PEASO_BENCH=1`, `PEASO_PRIVESC_BENCH=1` |

A quick static check that also runs in CI:

```bash
python -m pytest --noconftest -q tests/test_peaso_undefined_names.py
```

## How CI runs the suite

The Python job installs pinned dependencies and the external tools above, then splits the
suite into 32 deterministic shards:

```bash
python scripts/pytest_shard.py --shard 0 --shards 32 -- \
  -q -p no:cacheprovider -n auto --dist loadfile -rs --junitxml=pytest-report.xml
python scripts/check_test_skips.py pytest pytest-report.xml
```

- `pytest_shard.py --verify` checks that every test belongs to exactly one shard.
- `check_test_skips.py` fails the build if a test was skipped for a reason that is not on its
  allowlist, or if an allowed reason is used more often than its budget. A missing dependency
  therefore fails CI instead of silently shrinking coverage.
- Shard 0 also runs the performance gate `tests/test_peaso_perf_benchmark.py`.

## Frontend tests

```bash
cd frontend
npm ci
npm run typecheck
npm run build
npx playwright install --with-deps chromium
PLAYWRIGHT_JSON_OUTPUT_NAME=playwright-results.json npx playwright test --reporter=list,json
python ../scripts/check_test_skips.py playwright playwright-results.json
```

CI sets `PEASO_API_ORIGIN=http://127.0.0.1:9` so any test that accidentally needs a real API
fails. Specs that need a live server are skipped unless `PEASO_LIVE_TOKEN` and related
variables are set.

## Testing against real clouds

Live tests are manual. Use your own disposable test identities with the read-only access in
[permissions.md](permissions.md), scan a small scope, and delete any test identities and
resources afterwards. Never commit real account IDs, tokens or snapshots from real accounts.

## Best practices

- Write the PASS, FAIL and UNKNOWN cases for every new check.
- Prefer one realistic snapshot fixture over many mocked internals.
- Delete tests that only detect changes; replace them with a behaviour test if the behaviour matters.
- Keep each test fast; mark long benchmarks behind their opt-in variable.
- Run the relevant shard locally with `scripts/pytest_shard.py` before pushing large changes.
