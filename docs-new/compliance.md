# Compliance frameworks

PEASO CSPM groups native check results under compliance frameworks so you can read them in a
familiar structure. This page explains where those mappings come from and how to read them.

**A framework view is not a certification.** Mappings are thematic links between a framework
requirement and native checks that look at related settings. Many requirements also need
process evidence, documents or human review that no scanner can collect.

## Sources

The framework catalog is `peaso/rulepacks/framework_catalog.json`. Each row describes one
framework version for one provider and records:

- `name`, `family`, `provider`, `version`.
- `repository` and `source_revision`: the upstream project and pinned commit the mapping was
  reviewed from. Sources are `prowler-cloud/prowler` and the Turbot Steampipe/Powerpipe
  compliance and perimeter mods.
- `native_check_ids`: the native checks mapped to the framework.
- Requirement counts: total requirements, how many are partially automated, how many are
  `manual`.
- `status`:
  - `partially_supported`: some requirements map to native checks; the rest are manual or not covered.
  - `pending`: tracked but not yet mapped.
  - `out_of_scope`: the framework targets a platform the scanner does not read (for example
    Alibaba Cloud, Microsoft 365, Google Workspace, GitHub, Oracle Cloud, Okta).

Families covered for AWS, GCP, Azure and Kubernetes include CIS benchmarks, NIST 800-53
(Rev. 4 and 5), NIST 800-171, NIST CSF, PCI DSS, SOC 2, HIPAA, ISO 27001, FedRAMP, GDPR, C5,
ENS, NIS2, KISA-ISMS-P, MITRE ATT&CK, AWS Foundational Security Best Practices, AWS
Well-Architected (security and reliability), Kubernetes NSA/CISA hardening guidance, and
Prowler ThreatScore.

Two native frameworks are also available:

- **HackTricks Cloud Best Practices** (selector `hacktricks`).
- **NIST 800-53** (selector `nist_800_53`).

## Using frameworks

```bash
peaso catalog --format markdown -o catalog.md                         # list frameworks and checks
peaso scan --snapshot snap.json --frameworks hacktricks -o r.json
peaso scan --snapshot snap.json --frameworks "CIS Amazon Web Services Foundations Benchmark v3.0.0"
```

Use the exact framework name shown by `peaso catalog` or `GET /api/catalog/frameworks`.
In the web app, the **Hardening & Compliance** page lets you pick a framework and see its
requirements with the mapped native results.

## How results are shown

- A requirement with mapped checks shows those checks' statuses. Any `FAIL` means at least one
  mapped setting failed. `UNKNOWN` or `DENIED` mean the evidence was incomplete.
- A requirement marked `manual` has no automatic result; it needs your own review.
- `PASS` on all mapped checks does not mean the requirement is met. It means the settings the
  scanner can read look correct.

## Maintaining mappings

The runtime only reads the static JSON files. They are built offline by scripts that never
execute upstream code:

| Script | Purpose |
| --- | --- |
| `scripts/peaso_compliance_audit.py` | Enumerate requirements from pinned upstream sources into an audit matrix |
| `scripts/peaso_compliance_compile.py` | Compile reviewed mappings into runtime metadata |
| `scripts/peaso_compliance_materialize.py` | Build catalog views from the compiled pack and the live check registry |
| `scripts/peaso_compliance_merge_new.py` | Stage reviewed descriptions for new checks before compilation |

When a native check is added or changed, update the mapping through these scripts rather than
editing the generated JSON by hand.

## Best practices

- Present framework results as "settings related to this requirement", never as "compliant".
- Review `manual` requirements yourself; they are often the most important process controls.
- Resolve `UNKNOWN` and `DENIED` results before relying on a framework view.
- Pin the framework version you report against and keep it the same between scans you compare.
