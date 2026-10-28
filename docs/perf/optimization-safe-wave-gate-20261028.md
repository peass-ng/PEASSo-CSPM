# Optimization wave without ECR content changes

This local candidate is based on `d7a9fd42` and retains the base versions of
`peaso/collectors/aws_package_content_indicators.py`,
`peaso/collectors/aws_image_capture_20261022.py`, and
`peaso/secret_scanning_adaptive.py`. It excludes repository overlap, adaptive
clean-byte filtering, digest capture reuse, and four-lane layer fetch. This
protects the bf67 incomplete-image cohort (23 collected incomplete package
indicators, seven with 146 positive references, plus 11 projection-unavailable)
until a pinned Linux full-output and private-binding parity gate is available.

Selected non-ECR changes: saved-report inventory indexing, streaming Markdown,
account-bound S3 policy read reuse, final AWS snapshot ownership, automatic
content-scope timing, count-only coverage comparator, terminal cumulative
checkpoint deferral, and immutable ECS task-definition read reuse. The ECS raw
cache retains its original 96 MiB ceiling and uses the existing endpoint
limiter admission. The count-only comparator is a review aid, not proof of
finding or private-evidence parity.

Saved-replay evidence: inventory indexing preserved the exact 211,024,918-byte
report and changed paired evaluation wall 54.98→44.29s. Markdown preserved the
exact 861,313,699-byte export and changed local render wall 54.08→37.32s,
CPU 39.94→33.54s. AWS final snapshot ownership preserved the 391,103-item
snapshot ID and changed local builder wall 5.633→3.419s. The S3 `wiki` pair
preserved its output digest and 16 bucket rows, with calls 241→225, wall
22.640→13.422s, CPU 1.344→1.175s; measured RSS rose 229.9→244.3 MB, so
full-scan resource cost remains a gate. A ten-definition ECS sample retained
its result digest and changed physical calls 20→10; it used the original
256 MiB candidate, and the sample fits this branch's 96 MiB cap. Full-scan
cache hit rate remains unmeasured.

The terminal change keeps raw batches and final watermark durable and lets the
analyzer render the successful final report. Interrupted collection still
publishes its latest partial report on close. Its bf67 Collect saving of
218–228s is projected, not measured. The branch has no proven t0–900
critical-path saving large enough to reach 800s Collect.

Integration gates on this branch: 126 focused collector/analyzer/lifecycle
tests passed; six combined release gate tests passed; strict source import
passed; API source inventory has zero diff; compliance catalog check reports
`stale=[]`; the privilege display binding was regenerated. No production
scan, cloud write, model call, push, or deployment was made for this branch.
