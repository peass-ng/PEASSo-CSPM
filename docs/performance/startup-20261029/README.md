# Cross-cloud startup, 2026-10-29

The saved scans spend 76.959–95.133 seconds between workflow start and the
collector's DDB claim. Faster scheduler polling alone cannot remove this interval.
The image contains removable wheel-build residue; the candidate removes it in
the pip installation layer without changing runtime code or dependencies.

| Saved cloud scan | Queued → workflow | Workflow → Collect | Queued → Collect |
| --- | ---: | ---: | ---: |
| AWS a51ff5a9 | 41.088s | 78.811s | 119.899s |
| GCP 52588fc3 | 4.171s | 76.959s | 81.130s |
| Azure c89fd875 | 4.463s | 94.263s | 98.726s |
| K8s e1095371 | 4.484s | 95.133s | 99.617s |

`saved-startup-profile.json` records full scan IDs and SHA256 of the exact private
source receipts. `profile_saved_startup.py` reproduces the table without cloud
access. It also supports a supplied ECS task record through its `profile` function
and refuses incomplete or reversed timestamps. Three focused tests cover missing
evidence, interval reconciliation and invalid ordering.

The queued-to-workflow column includes scheduler wait, admission, authentication
and dispatch. It is an upper bound on the saving from eliminating that entire
path, rather than a measurement of scheduler polling alone. For GCP/Azure/K8s,
even perfect dispatch saves at most 4.171/4.463/4.484 seconds on these scans.
For AWS the corresponding upper bound is 41.088 seconds. Guaranteed production
startup saving from this candidate is **0 seconds** until a paired production
measurement exists; no before/after seconds or cost reduction is asserted.

## Attribution limits

`infra/aws/api.tf` schedules one Lambda per minute. `WorkflowDispatcher.dispatch`
in `peaso/storage/runtime.py` attempts immediate workflow start, subject to auth
and admission, and leaves failed attempts to the scheduler. Increasing polling
frequency would add invocations and cannot remove the measured post-workflow
interval; it is not part of this change.

The post-workflow column combines Step Functions submission, ECS placement and
provisioning, image download/extraction, container entrypoint/Python imports and
storage/auth initialization before claim. It must not be labeled image-pull time.
Exact separation needs saved ECS `createdAt`, `pullStartedAt`, `pullStoppedAt`,
`startedAt` and the workflow start. `GetExecutionHistory`'s successful ECS output
may retain these even after stopped tasks cease being describable. No such
records were available in the local receipts during the initial diagnosis.

AWS profiles `wiki` and `Hacktricks-Admin`, and the existing exported deployment
credentials, were expired. No login, refresh, new workflow, Lambda invocation,
scan, deployment or cloud mutation was attempted. The coordinator was asked for
an authenticated read-only path using question `msg_3127ef2d1281`.

The saved collector `worker.startup` spans are AWS 9.157s, GCP 9.080s and Azure
9.736s (`child-startup-spans.json`). They occur **after** Collect begins:
`Worker.run_once` claims the job before starting its child, and `DynamoStore.claim`
marks it collecting. These spans cover child imports/credential verification;
subtracting them from queue-to-Collect would be incorrect. The saved K8s receipt
does not contain this span.

## Image cleanup and validation

`infra/aws/Dockerfile.worker` now removes `/app/build` immediately after successful
pip installation, in the same RUN instruction. Removing it in a later layer would
leave the original bytes in the image. The source tree, installed package,
distribution metadata, CLIs, proof steps, bytecode, model settings and task
resource allocations are retained. No Terraform or IAM file changed.

The existing local immutable Linux/amd64 worker image was
`202533532952.dkr.ecr.us-east-1.amazonaws.com/hacktricks-cspm-worker@sha256:eca921607a21ead7acf1ad02c55a6d151cc2e252fc14db8300db8dcfc47b38d6`.
This is a local historical image probe, not proof of the exact image used by the
four saved scans or the latest deployment. It was run in a disposable container
with network disabled, using `probe_build_residue.py`:

- Removed 2,550 build files containing **220,281,188 logical bytes** (~210.1 MiB).
- Removed subtree tar size 224,921,600 bytes; gzip level-6 proxy 34,847,043 bytes
  (~33.2 MiB). This is not a measured OCI compressed-layer delta.
- All **29,816 retained app/dependency files**, **1,155,733,686 bytes**, had the same
  aggregate SHA256 before and after:
  `1e6b8a8f24f29f1491a6a1dcb7f22ff6387cef7f5332d176879f985aede768ff`.
- Worker, engine, checks, AI runner and scheduler imports succeeded from `/app`;
  installed distribution version remained `0.1.0`.
- Zero cloud/model calls and zero paid IAM Access Analyzer operations.

`build-residue-probe.json` is the numeric receipt. The cleanup does not increase
task count/CPU/memory or change findings, model inputs, effort or turns. Its only
measured benefit is removal of redundant image content; network transfer and
startup seconds need the coordinator's exact-image build/deployment gate.

Validation commands:

```sh
python3 -m unittest discover -s docs/performance/startup-20261029 -p 'test_*.py' -v
docker run --rm --platform linux/amd64 --network none --user 0 \
  --entrypoint python -e PEASO_SOURCE_ATTESTATION=trusted \
  -v "$PWD/docs/performance/startup-20261029/probe_build_residue.py:/probe.py:ro" \
  eca921607a21 /probe.py
git diff --check
```

The full current Docker image was not rebuilt: the offline probe isolates the
cleanup while retaining exact existing dependencies. Root owns release source
attestation, exact image-size verification, deployment and paired startup timing.
