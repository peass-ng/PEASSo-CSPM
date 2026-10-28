# AWS S3 policy read reuse (2026-10-28)

The saved bf67 collector SDK metrics record 296 `GetBucketPolicy` calls for 148 buckets, 199.3 additive SDK seconds and 133 SDK retries. The native bucket reader already resolves each bucket's home Region. The resource policy recipe previously repeated the policy read from the scan Region with different request arguments, so the scan cache could not coalesce the two consumers.

The native bucket read now supplies `ExpectedBucketOwner` from the authenticated account. The resource policy recipe resolves the same home Region via the cached `GetBucketLocation` response and uses the same policy request key. If location lookup is incomplete, the recipe keeps its prior scan Region fallback. Both readers still request the full policy document, and the owner guard remains in place.

Read-only `wiki` bench: `PYTHONPATH=. python3 /tmp/bench_aws_s3_policy_reuse.py`, account `202533532952`, us-east-1, 16 buckets. The bench read the native bucket projection and the S3 policy recipe through one `Requests` instance. It reports counts and a SHA-256 of their JSON output, never policy contents.

| Metric | Before | After |
| --- | ---: | ---: |
| Wall seconds | 22.640 | 13.422 |
| CPU seconds | 1.344 | 1.175 |
| Peak RSS bytes | 229,916,672 | 244,269,056 |
| SDK calls | 241 | 225 |
| Cache hits | 1 | 33 |
| Bucket rows | 16 | 16 |
| Resource policy rows | 15 | 15 |
| Both statuses | collected | collected |
| Output SHA-256 | `3f750ceb516aafa18aecae9ceba5387501013b000d1f0ff94baed23d0e4da93f` | same |

The 16 avoided calls are one policy read per bucket. Peak RSS rose by 14.4 MB in these separate processes, so this benchmark supports a wall and call win, not a memory win. A focused cross-Region test checks that the two readers issue one account-bound policy request in the bucket's home Region; the existing bucket concurrency test also passed (2/2 total).

Broad test collection is currently obstructed by an unrelated source admission pin in `peaso/checks` that rejects the earlier ECR module change. Direct policy coverage audit is separately obstructed by four stale exclusions for the installed SDK. Neither obstruction appeared in the focused tests or live bench. No production scan was run in this worktree.

The saved bf67 runtime also shows a 314.3-second public checkpoint during `worker.collect`, including 222.7 seconds in Markdown publication; `worker.final_snapshot` took 24.6 seconds. The synthetic descriptor replay of the configuration redaction finalizer on the saved 1,292-collection snapshot took 29.954 wall / 12.628 CPU seconds and produced unchanged rows. Thus the 300-second late interval cannot be assigned to snapshot construction alone. The production ≤800-second target and zero incomplete collections remain unverified and unmet by the available bf67 baseline.
