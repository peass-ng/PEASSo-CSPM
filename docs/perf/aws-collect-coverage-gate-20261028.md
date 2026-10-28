# AWS Collect coverage comparison gate (2026-10-28)

The bf67 snapshot has 1,292 unique `(type, scope)` collection identities and 391,103 items. A count-only gate now compares a guarded follow-up snapshot with bf67 without printing account, resource, policy, or secret values. It detects missing or added identities, service/account/global binding changes, complete-to-incomplete status regressions, and partial-to-unreadable regressions. It reports item totals and the literal number of incomplete rows. Plain and gzip JSON snapshots are accepted.

Run after root's guarded full scan:

```sh
python3 scripts/compare_aws_collect_coverage.py \
  /Users/carlospolop/peaso-work/replay/aws-bf67-collected-snapshot.json.gz \
  /path/to/new-full-aws-snapshot.json.gz \
  --require-zero-incomplete
```

The command exits nonzero unless all 1,292 identities and bindings match, no readable status regresses, and the new snapshot has zero incomplete rows. Omitting `--require-zero-incomplete` checks coverage preservation only; it cannot prove the stated zero-incomplete target.

Self-comparison of the saved bf67 snapshot passed identity and status preservation with 1,292 identities, zero missing/added/binding changes/regressions, matching identity digest `e09ecb46f81fc15e6295b94e4201238e9c312db78fc89955e9a9f364c3f1c8cf`, and 391,103 items on each side. It also reports **198 incomplete rows** (70 not collected, 6 partial, 56 denied, 66 unknown). Thus the literal zero-incomplete target is not true for bf67; a new full scan must establish it independently. A focused synthetic test verifies detection of missing identity, complete-to-incomplete and partial-to-unreadable regressions, and the strict zero-incomplete gate.

This gate does not measure production wall time or API calls; collector SDK and runtime metrics must accompany the follow-up snapshot. No production scan, cloud write, push or deploy was performed here.
