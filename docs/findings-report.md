# Findings Report

AI-enabled scans compile a Findings Report after the selected Network Architecture
and Top 10 Actions analyses finish. The report is enabled by default and can be
turned off independently in scan and schedule settings with
`ai_findings_report_enabled: false`. `ai_enabled: false` disables all model work.
Progressive Network-only invocations do not start the compiler.

The full agent prompt and runtime configuration are in
[`peaso/ai/agents/findings_report.yaml`](../peaso/ai/agents/findings_report.yaml).
It uses the existing best-quality model alias and high thinking effort. It runs
in the existing isolated agent runtime, with captured evidence and no live cloud
credentials. The shared deadline reserves time for compilation and publication.

The local context contains only FAIL check results. It also supplies actionable
least-privilege recommendations, privilege-escalation paths and prioritized
actions supported exclusively by FAIL results. Resource configuration and
IAM/network relationships are limited to explicit references and two dependency
hops around assigned evidence. Regeneration writes fresh issue text from current evidence and preserves issue
IDs when the confirmed reference sets match.
The opening overview previews at most 12 cases per area; full case membership and
evidence are indexed for targeted, paginated access. Findings are grouped by
root cause and remediation, independently of the prioritized actions limit.
Check-result totals, FAIL totals and evidence-source totals are not vulnerability
counts; only the consolidated issues are counted as report issues. Every required source (native FAIL, least-privilege candidate, escalation
edge and top action) must appear once in an issue or a documented exclusion.
Unavailable upstream stages are retained as limitations. The compiled report does
not replace native verdicts.

Affected resources come from the directly bound subjects of failed evaluations.
Least-privilege suggestions, graph endpoints, action groups and related inventory
remain evidence. They do not supply affected resources. Configuration scopes
are shown separately from individual resources. The platform deduplicates resources
by their scoped provider identity, and agents cannot edit the resulting list.
When a check only verifies a relationship or a joined evaluator lacks a direct
subject binding, the report identifies its asset scope as incomplete. Regenerate
individual reports from their saved evidence before using their asset counts in
a new combined report.

The platform deterministically pre-generates one finding containing all positive
leak observations and another containing all positive image CVE observations before
any agent invocation. Their complete native evidence remains linked; leak values
are omitted from generated prose. These findings survive agent failure. The agent
receives only its assigned observations and actions; the deterministic findings
and their source records stay outside its workspace. Its validated issues are
appended to those findings by the platform.

The prompt explicitly groups encryption observations into one finding, logging
and monitoring gaps into one, and backup and recovery gaps into one, with exact
resource-specific observations and fixes inside each theme. Suggestions and
conditional graph paths can support an issue backed by a failed check. Combined
reports include only confirmed issues from their source reports. General
preventive hardening is informational.

Medium and higher vulnerability ratings require a structured consequence,
supported prerequisites and an affected asset from a cited failed check.
High and Critical also apply the rubric's reachability and impact thresholds.
Low covers limited impact and unresolved material prerequisites. Info is used
for preventive hardening.

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

## Combined reports

The Findings Report view provides a **Combine different reports** dialog. Choose
2–20 completed assessment reports from the current workspace. Each combination
freezes the selected report versions, including their issue text, source IDs and
limitations; regenerating an original report does not rewrite an existing
combination. Changed selections are rejected so the user can refresh them before
starting. Combined reports have their own history, source list, status, issue table,
search and severity filters. Each source assessment lists its combinations in the
Combined reports tab; users can also show all workspace combinations.

The isolated `report_combination` agent receives compiled issues and report metadata
only, with small previews and paginated local lookups. Its provider-neutral prompt
is in `peaso/ai/agents/report_combination.yaml`. It consolidates matching security
themes across scopes, preserving asset identities, individual fixes, dates and
impact prerequisites for confirmed weaknesses. The prompt keeps unresolved
controls out of vulnerability prose, including caveats in older source reports.
Medium and higher ratings cite one confirmed source issue with a sufficient
rating and the affected asset. Where the source has structured severity evidence,
the combination carries it forward exactly. Older issues can support a rating
with adequately documented impact in their description and impact fields.
Every source issue must be referenced exactly once;
leaks and image CVEs each remain one combined finding when present. Validation
preserves the highest supporting severity and repeats at the worker boundary.
Source-issue drawers read frozen originals, so identical issue IDs in different
assessments and later source regenerations remain unambiguous.

Hosted combinations use the existing role-free agent runtime through a report-only
workflow branch. Generation is tenant-scoped and fenced; read-only workspace access
cannot create combinations. Workspace cleanup waits for active combinations and
removes completed combination metadata and artifacts with the other workspace data.

## PDF downloads

Choose **PDF** from the **Download** menu in a completed Findings Report to
export a single document covering all its issues. The same export is available inside a completed combined
report. Page and severity filters in the issue table do not limit the PDF. The
document includes the assessment scope and schedule, a linked contents page, a
severity and service overview, and evidence in each finding. Each finding starts
on a new page. The PDF lists up to 25 directly affected assets per issue. For
larger sets it lists 10 assets and gives the remaining count.
