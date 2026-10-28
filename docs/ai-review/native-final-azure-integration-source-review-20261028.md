# Azure native-final source integration review

The v2 saved-pair audit qualified 124 Hardening check IDs against the exact
`a79ff6f9` snapshot. The integration branch retains every check source file at
the audited digest. Only `peaso/collectors/azure.py` differs from the worker's
source proof: the integrated collector adds read-only Exposure facts for
MySQL/Redis firewall child rules, App Service authentication, and Compute
Gallery detail. It does not remove or alter fields used by the selected
Hardening evaluators.

The v2 proof and pending manifest pin the integrated collector digest
`8727e003b43da456c709908dae7e9fbd84824ade6fdf4ea8fabaed6f5a781d13`.
The updated proof digest is
`5a2d5116a35c8b567d4e4004994618326d0a0a03a3f5a45354024a051d5415cb`.
Hosted qualification and runtime admission remain off pending the paired gate.
