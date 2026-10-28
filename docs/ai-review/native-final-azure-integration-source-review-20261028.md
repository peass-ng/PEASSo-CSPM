# Azure native-final source integration review

The v2 saved-pair audit qualified 124 Hardening check IDs against the exact
`a79ff6f9` snapshot. The integration branch retains every check source file at
the audited digest. Only `peaso/collectors/azure.py` differs from the worker's
source proof: the integrated collector adds read-only Exposure facts for
MySQL/Redis firewall child rules, App Service authentication, and Compute
Gallery detail. It does not remove or alter fields used by the selected
Hardening evaluators.

The v2 proof and pending manifest pin the integrated collector digest
`843142e57cc7148f698096a0d66ffc6391690944129d7468e689d631bf75c90d`.
The updated proof digest is
`b71755e126721c8b34825e23818cc9805919dd7e96ec71fbf8564fd7d7a29d12`.
Hosted qualification and runtime admission remain off pending the paired gate.
