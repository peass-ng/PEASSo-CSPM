# Select content analyses independently

`POST /api/scans` and assessment schedules accept `leaks_enabled` and `images_enabled`. These switches select configured content and image readers independently of Hardening & Compliance categories, check IDs, and framework filters.

```json
{
  "connector_id": "your-connector-id",
  "categories": ["hardening", "exposure", "network"],
  "frameworks": ["CIS"],
  "leaks_enabled": true,
  "images_enabled": true,
  "ai_enabled": true
}
```

The connector must already enable the corresponding scanner. Readers that require exact target selections or separate cluster/source authentication retain those requirements. Existing bounded native configuration and source-reference readers use the selected cloud scopes and recorded resource identities. The API records the concrete native check IDs in `content_checks`; advanced clients may select a subset with that field while omitting the feature switches. Public connector metadata lists eligible IDs under `content_scan_checks.leaks` and `.images`, without exposing credentials or target contents.

With Leaks enabled, supported workload literals are discovered from the selected native inventory: AWS Lambda environments and supported ECS/build workload settings, Azure application settings and container workloads, and Kubernetes workload literals. These readers need no hand-picked target list. Supplying their selector option keeps that explicit selection authoritative; an empty selection never expands to automatic discovery. Other source, log, image, and cluster readers keep their existing selection and authentication requirements.

Use `categories: []` with an enabled content stage for a content-only assessment. Its readers and findings remain selected even when the Hardening & Compliance framework filter excludes their original checklist category. A false stage switch disables that scanner on a copy of the connector for this run; the saved connector is unchanged. Omitting the new fields preserves existing explicit-check requests.

Content readers retain their existing target validation, cloud scope boundaries, deadlines, detector settings, and permissions. The switches do not authorize arbitrary locations or validate discovered credentials. Completed content sections use the existing durable checkpoint and private-evidence mechanisms. Schedules and resumed scans retain the recorded stage selection.
