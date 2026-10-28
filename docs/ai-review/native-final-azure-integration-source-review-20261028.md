# Azure native-final source integration review

The v2 saved-pair audit qualified 124 Hardening check IDs against the exact
`a79ff6f9` snapshot. The integration branch retains every check source file at
the audited digest. Only `peaso/collectors/azure.py` differs from the worker's
source proof: the integrated collector adds read-only Exposure facts for
MySQL/Redis firewall child rules, App Service authentication, and Compute
Gallery detail. It does not remove or alter fields used by the selected
Hardening evaluators.

The v2 proof and pending manifest pin the integrated collector digest
`b433b0e8568497e108992ff09fb1303b6cb9c4fdbb104c36a1baeab53c888638`.
The updated proof digest is
`30d4444818a1fe8541afdb11098e1df1b243eec49e3c438dce166b71905054a2`.
Hosted qualification and runtime admission remain off pending the paired gate.
