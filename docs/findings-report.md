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

The local context contains failed observations, actionable least-privilege
recommendations, privilege-escalation paths, accepted network findings and relevant
prioritized actions. Passed checks, unrelated inventory and bulk snapshot metadata
are omitted. Resource configuration and IAM/network relationships are limited to
explicit references and two dependency hops around assigned evidence. Relevant
uncertain observations and coverage gaps remain available through local lookups.
The opening overview previews at most 12 cases per area; full case membership and
evidence are indexed for targeted, paginated access. Findings are grouped by root cause and remediation, without a 15-issue
limit. Check-result totals, FAIL totals and evidence-source totals are not vulnerability
counts; only the consolidated issues are counted as report issues. Every required source (native FAIL, least-privilege candidate, escalation
edge and top action) must appear once in an issue or a documented exclusion.
Unavailable upstream stages are retained as limitations. The compiled report does
not replace native verdicts.

The platform deterministically pre-generates one finding containing all positive
leak observations and another containing all positive image CVE observations before
any agent invocation. Their complete native evidence remains linked; leak values
are omitted from generated prose. These findings survive agent failure. The agent
receives only its assigned observations and actions; the deterministic findings
and their source records stay outside its workspace. Its validated issues are
appended to those findings by the platform.

The prompt explicitly groups encryption observations into one finding, logging
and monitoring gaps into one, and backup and recovery gaps into one, with exact
resource-specific observations and fixes inside each theme. Suggestions and conditional graph paths cannot alone
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
issue details and links to supporting evidence. Completed assessments expose a Generate/Regenerate report action. A generation
request immediately replaces the active report with an empty pending report;
completion publishes newly created issue IDs. Generation uses the saved snapshot,
accepted architecture review and prioritized actions without collection or changing
native assessment results. Tenant-scoped compare-and-swap state prevents concurrent
runs and stale publication. Hosted requests use a report-only branch of the existing
assessment workflow; the normal analyzer runs report compilation after the other
analyses. Older assessments can generate a report on demand.

Validation failures receive bounded correction attempts. A failed compiler
marks AI output partial while keeping the scan's native findings available.
