# Findings Report

AI-enabled scans compile a Findings Report after the selected Network Architecture
and Top 15 Actions analyses finish. The report is enabled by default and can be
turned off independently in scan and schedule settings with
`ai_findings_report_enabled: false`. `ai_enabled: false` disables all model work.
Progressive Network-only invocations do not start the compiler.

The full agent prompt and runtime configuration are in
[`peaso/ai/agents/findings_report.yaml`](../peaso/ai/agents/findings_report.yaml).
It uses the existing best-quality model alias and high thinking effort. It runs
in the existing isolated agent runtime, with captured evidence and no live cloud
credentials. The shared deadline reserves time for compilation and publication.

The lossless local context includes all native finding statuses, resources,
least-privilege recommendations, IAM and privilege-escalation maps, network
configuration, the accepted architecture review, Top 15 Actions and collection
coverage. Findings are grouped by root cause and remediation, without a 15-issue
limit. Check-result totals, FAIL totals and evidence-source totals are not vulnerability
counts; only the consolidated issues are counted as report issues. Every required source (native FAIL, least-privilege candidate, escalation
edge and top action) must appear once in an issue or a documented exclusion.
Unavailable upstream stages are retained as limitations. The compiled report does
not replace native verdicts.

All detected leaks belong to one issue, with safe locations and no matched
secret values. All image CVEs belong to one issue, including immutable image
references and package details. Both grouping rules are validated against the
trusted source index. Suggestions and conditional graph paths cannot alone
support a confirmed issue. General preventive hardening is informational.

The historical report review informed these writing rules: distinguish settings
from demonstrated exploitation; inspect actual scope and compensating controls;
do not equate missing usage with unused permissions; group overlapping controls;
include operational dependencies in remediation; and preserve package/runtime
uncertainty. Historical customer reports and customer data are not embedded in
the shipped prompt or examples.

The report is stored with the owning scan's existing AI artifact. The authenticated
`GET /api/scans/{id}/findings-report` endpoint filters the full issue set before
pagination and paginates exclusions independently (`exclusion_offset`). The
existing `/ai` endpoint returns only report status and total, keeping sidebar
polling bounded. The Security Insights page provides search, severity filtering,
issue details and links to supporting evidence. Older scans show an unavailable
report state; this change does not mutate or automatically backfill them.

Validation failures receive bounded correction attempts. A failed compiler
marks AI output partial while keeping the scan's native findings available.
